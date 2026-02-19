// SPDX-License-Identifier: GPL-2.0
/*
 * AI-Sentinel LSM - AEGIS-OS
 * Linux Security Module for real-time behavioral analysis
 *
 * Copyright (c) 2025 AEGIS-OS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/proc_ns.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

#include "ai_sentinel.h"

/* Module information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AEGIS-OS Project");
MODULE_DESCRIPTION("AI-Sentinel LSM - Real-time behavioral analysis");
MODULE_VERSION(AI_SENTINEL_VERSION);

/* Global state */
static struct ai_sentinel_state sentinel_state;

/* Forward declarations for security hooks */
static struct security_hook_list ai_sentinel_hooks[] = {
	LSM_HOOK_INIT(bprm_check_security, ai_sentinel_bprm_check_security),
	LSM_HOOK_INIT(task_free, ai_sentinel_task_free),
	LSM_HOOK_INIT(file_permission, ai_sentinel_file_permission),
	LSM_HOOK_INIT(socket_connect, ai_sentinel_socket_connect),
	LSM_HOOK_INIT(socket_bind, ai_sentinel_socket_bind),
	LSM_HOOK_INIT(task_fix_setuid, ai_sentinel_task_fix_setuid),
	LSM_HOOK_INIT(ptrace_access_check, ai_sentinel_ptrace_access_check),
};

/* Utility function - event type to string */
char *ai_sentinel_event_type_str(enum ai_sentinel_event_type type)
{
	static const char * const event_types[] = {
		[AI_SENTINEL_EVENT_EXEC] = "EXEC",
		[AI_SENTINEL_EVENT_EXIT] = "EXIT",
		[AI_SENTINEL_EVENT_FORK] = "FORK",
		[AI_SENTINEL_EVENT_FILE_OPEN] = "FILE_OPEN",
		[AI_SENTINEL_EVENT_FILE_WRITE] = "FILE_WRITE",
		[AI_SENTINEL_EVENT_SOCKET_CONNECT] = "SOCKET_CONNECT",
		[AI_SENTINEL_EVENT_SOCKET_BIND] = "SOCKET_BIND",
		[AI_SENTINEL_EVENT_PRIV_ESCALATE] = "PRIV_ESCALATE",
		[AI_SENTINEL_EVENT_MMAP_EXEC] = "MMAP_EXEC",
		[AI_SENTINEL_EVENT_PTRACE] = "PTRACE",
	};

	if (type >= AI_SENTINEL_EVENT_MAX)
		return "UNKNOWN";
	return (char *)event_types[type];
}

/* Utility function - severity to string */
char *ai_sentinel_severity_str(enum ai_sentinel_severity sev)
{
	static const char * const severities[] = {
		[AI_SENTINEL_SEV_INFO] = "INFO",
		[AI_SENTINEL_SEV_LOW] = "LOW",
		[AI_SENTINEL_SEV_MEDIUM] = "MEDIUM",
		[AI_SENTINEL_SEV_HIGH] = "HIGH",
		[AI_SENTINEL_SEV_CRITICAL] = "CRITICAL",
	};

	if (sev > AI_SENTINEL_SEV_CRITICAL)
		return "UNKNOWN";
	return (char *)severities[sev];
}

/* Calculate event severity based on type and context */
enum ai_sentinel_severity ai_sentinel_calculate_severity(struct ai_sentinel_event *event)
{
	struct ai_sentinel_proc *proc;
	enum ai_sentinel_severity sev = AI_SENTINEL_SEV_INFO;

	/* Base severity on event type */
	switch (event->type) {
	case AI_SENTINEL_EVENT_EXEC:
		sev = AI_SENTINEL_SEV_LOW;
		break;
	case AI_SENTINEL_EVENT_EXIT:
		sev = AI_SENTINEL_SEV_INFO;
		break;
	case AI_SENTINEL_EVENT_FORK:
		sev = AI_SENTINEL_SEV_INFO;
		break;
	case AI_SENTINEL_EVENT_FILE_OPEN:
		/* Check if opening sensitive file */
		if (strstr(event->data.file.path, "/etc/shadow") ||
		    strstr(event->data.file.path, "/etc/passwd") ||
		    strstr(event->data.file.path, "/root/"))
			sev = AI_SENTINEL_SEV_MEDIUM;
		else
			sev = AI_SENTINEL_SEV_LOW;
		break;
	case AI_SENTINEL_EVENT_FILE_WRITE:
		/* Writing to system files is more severe */
		if (event->data.file.path[0] == '/' &&
		    (strstr(event->data.file.path, "/etc/") ||
		     strstr(event->data.file.path, "/bin/") ||
		     strstr(event->data.file.path, "/sbin/") ||
		     strstr(event->data.file.path, "/lib/") ||
		     strstr(event->data.file.path, "/usr/")))
			sev = AI_SENTINEL_SEV_HIGH;
		else
			sev = AI_SENTINEL_SEV_MEDIUM;
		break;
	case AI_SENTINEL_EVENT_SOCKET_CONNECT:
		/* Check for suspicious ports */
		if (event->data.socket.dport == htons(4444) ||  /* Metasploit */
		    event->data.socket.dport == htons(6667) ||  /* IRC */
		    event->data.socket.dport == htons(31337))   /* Backdoor */
			sev = AI_SENTINEL_SEV_CRITICAL;
		else
			sev = AI_SENTINEL_SEV_LOW;
		break;
	case AI_SENTINEL_EVENT_SOCKET_BIND:
		sev = AI_SENTINEL_SEV_LOW;
		break;
	case AI_SENTINEL_EVENT_PRIV_ESCALATE:
		sev = AI_SENTINEL_SEV_HIGH;
		break;
	case AI_SENTINEL_EVENT_MMAP_EXEC:
		/* W+X mappings are suspicious */
		if (event->data.mmap.prot & PROT_WRITE &&
		    event->data.mmap.prot & PROT_EXEC)
			sev = AI_SENTINEL_SEV_HIGH;
		else
			sev = AI_SENTINEL_SEV_MEDIUM;
		break;
	case AI_SENTINEL_EVENT_PTRACE:
		sev = AI_SENTINEL_SEV_MEDIUM;
		break;
	default:
		sev = AI_SENTINEL_SEV_LOW;
		break;
	}

	/* Adjust based on process trust score */
	rcu_read_lock();
	proc = ai_sentinel_proc_find(event->pid);
	if (proc) {
		/* Low trust processes increase severity */
		if (proc->trust_score < 30 && sev < AI_SENTINEL_SEV_HIGH)
			sev++;
		/* High trust processes can decrease severity */
		else if (proc->trust_score > 80 && sev > AI_SENTINEL_SEV_LOW)
			sev--;
	}
	rcu_read_unlock();

	return sev;
}

/* Initialize the AI-Sentinel LSM */
static int __init ai_sentinel_state_init(void)
{
	int ret;

	/* Initialize process list */
	INIT_LIST_HEAD(&sentinel_state.proc_list);
	spin_lock_init(&sentinel_state.proc_lock);

	/* Initialize event queue */
	INIT_LIST_HEAD(&sentinel_state.event_queue);
	spin_lock_init(&sentinel_state.event_lock);

	/* Initialize configuration */
	sentinel_state.config.enabled = true;
	sentinel_state.config.enforce_mode = false;  /* Start in monitoring mode */
	sentinel_state.config.log_all_events = true;
	sentinel_state.config.default_trust_score = AI_SENTINEL_TRUST_DEFAULT;
	sentinel_state.config.track_processes = true;
	sentinel_state.config.track_file_ops = true;
	sentinel_state.config.track_net_ops = true;
	sentinel_state.config.detect_anomalies = true;

	atomic_set(&sentinel_state.event_count, 0);

	/* Initialize netlink socket for userspace communication */
	ret = ai_sentinel_netlink_init();
	if (ret) {
		pr_err("AI-Sentinel: Failed to initialize netlink: %d\n", ret);
		return ret;
	}

	/* Initialize event workqueue */
	sentinel_state.event_wq = alloc_workqueue("ai_sentinel",
						   WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!sentinel_state.event_wq) {
		pr_err("AI-Sentinel: Failed to create workqueue\n");
		ai_sentinel_netlink_exit();
		return -ENOMEM;
	}

	INIT_WORK(&sentinel_state.event_work, ai_sentinel_event_flush);

	/* Initialize event timer */
	timer_setup(&sentinel_state.event_timer, ai_sentinel_event_timer_callback, 0);
	mod_timer(&sentinel_state.event_timer, jiffies + HZ / 10);  /* 100ms */

	return 0;
}

/* Module initialization */
int __init ai_sentinel_init(void)
{
	int ret;

	pr_info("AI-Sentinel LSM v%s initializing...\n", AI_SENTINEL_VERSION);

	/* Initialize state */
	ret = ai_sentinel_state_init();
	if (ret) {
		pr_err("AI-Sentinel: Failed to initialize state: %d\n", ret);
		return ret;
	}

	/* Register security hooks */
	security_add_hooks(ai_sentinel_hooks, ARRAY_SIZE(ai_sentinel_hooks),
			   AI_SENTINEL_NAME);

	/* Register sysfs interface */
	ret = ai_sentinel_sysfs_init();
	if (ret) {
		pr_err("AI-Sentinel: Failed to initialize sysfs: %d\n", ret);
		del_timer_sync(&sentinel_state.event_timer);
		destroy_workqueue(sentinel_state.event_wq);
		ai_sentinel_netlink_exit();
		return ret;
	}

	pr_info("AI-Sentinel LSM initialized successfully\n");
	pr_info("AI-Sentinel: Mode=%s, Process tracking=%s\n",
		sentinel_state.config.enforce_mode ? "ENFORCE" : "MONITOR",
		sentinel_state.config.track_processes ? "enabled" : "disabled");

	return 0;
}

/* Module cleanup */
void __exit ai_sentinel_exit(void)
{
	struct ai_sentinel_proc *proc, *tmp;
	struct ai_sentinel_event *event, *evt_tmp;

	pr_info("AI-Sentinel LSM shutting down...\n");

	/* Cleanup sysfs */
	ai_sentinel_sysfs_exit();

	/* Cleanup timer */
	del_timer_sync(&sentinel_state.event_timer);

	/* Cleanup workqueue */
	if (sentinel_state.event_wq) {
		flush_workqueue(sentinel_state.event_wq);
		destroy_workqueue(sentinel_state.event_wq);
	}

	/* Cleanup netlink */
	ai_sentinel_netlink_exit();

	/* Cleanup process list */
	spin_lock(&sentinel_state.proc_lock);
	list_for_each_entry_safe(proc, tmp, &sentinel_state.proc_list, list) {
		list_del(&proc->list);
		kfree(proc);
	}
	spin_unlock(&sentinel_state.proc_lock);

	/* Cleanup event queue */
	spin_lock(&sentinel_state.event_lock);
	list_for_each_entry_safe(event, evt_tmp, &sentinel_state.event_queue, list) {
		list_del(&event->list);
		kfree(event);
	}
	spin_unlock(&sentinel_state.event_lock);

	pr_info("AI-Sentinel LSM shutdown complete\n");
}

module_init(ai_sentinel_init);
module_exit(ai_sentinel_exit);
