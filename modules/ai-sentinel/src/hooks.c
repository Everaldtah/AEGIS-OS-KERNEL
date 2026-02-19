// SPDX-License-Identifier: GPL-2.0
/*
 * AI-Sentinel LSM - Security Hook Implementations
 *
 * Copyright (c) 2025 AEGIS-OS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/file.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/ptrace.h>

#include "ai_sentinel.h"

/* External global state */
extern struct ai_sentinel_state sentinel_state;

/**
 * ai_sentinel_bprm_check_security - Check binary execution
 * @bprm: Contains the binary being executed
 *
 * Called before a new program is executed. This is a key hook for
 * tracking process execution and analyzing new binaries.
 */
int ai_sentinel_bprm_check_security(struct linux_binprm *bprm)
{
	struct ai_sentinel_event *event;
	struct ai_sentinel_proc *proc;
	int ret = 0;

	if (!sentinel_state.config.enabled)
		return 0;

	/* Create event for execution */
	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (!event)
		return 0;  /* Don't block on memory failure */

	event->type = AI_SENTINEL_EVENT_EXEC;
	event->pid = current->pid;
	event->tgid = current->tgid;
	event->uid = current->cred->uid.val;
	event->gid = current->cred->gid.val;
	event->timestamp = ktime_get_ns();
	memcpy(event->comm, current->comm, TASK_COMM_LEN);

	/* Get executable path */
	if (bprm->file && bprm->file->f_path.dentry) {
		char *path = event->data.file.path;
		char *tmp = dentry_path_raw(bprm->file->f_path.dentry,
					    path, PATH_MAX);
		if (IS_ERR(tmp))
			path[0] = '\0';
		else if (tmp != path)
			memmove(path, tmp, strlen(tmp) + 1);
	}

	/* Calculate severity */
	event->severity = ai_sentinel_calculate_severity(event);

	/* Log event */
	if (sentinel_state.config.log_all_events ||
	    event->severity >= AI_SENTINEL_SEV_MEDIUM) {
		ai_sentinel_event_queue(event);
	}

	/* Add process to tracking list */
	ai_sentinel_proc_add(current->pid, current);

	/* Check enforce mode */
	if (sentinel_state.config.enforce_mode) {
		proc = ai_sentinel_proc_find(current->pid);
		if (proc && proc->trust_score < 10) {
			pr_warn("AI-Sentinel: Blocking execution of low-trust process %s (score=%d)\n",
				event->comm, proc->trust_score);
			ret = -EPERM;
		}
	}

	return ret;
}

/**
 * ai_sentinel_task_free - Process exit notification
 * @task: Task being freed
 *
 * Called when a task exits. Used to clean up tracking.
 */
void ai_sentinel_task_free(struct task_struct *task)
{
	struct ai_sentinel_event *event;

	if (!sentinel_state.config.enabled || !sentinel_state.config.track_processes)
		return;

	/* Create exit event */
	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (event) {
		event->type = AI_SENTINEL_EVENT_EXIT;
		event->pid = task->pid;
		event->tgid = task->tgid;
		event->uid = task->cred->uid.val;
		event->gid = task->cred->gid.val;
		event->timestamp = ktime_get_ns();
		memcpy(event->comm, task->comm, TASK_COMM_LEN);
		event->severity = AI_SENTINEL_SEV_INFO;

		ai_sentinel_event_queue(event);
	}

	/* Remove from tracking */
	ai_sentinel_proc_remove(task->pid);
}

/**
 * ai_sentinel_file_permission - File access permission check
 * @file: File being accessed
 * @mask: Access mode (MAY_READ, MAY_WRITE, MAY_EXEC)
 *
 * Called on file access operations. Monitors file I/O patterns.
 */
int ai_sentinel_file_permission(struct file *file, int mask)
{
	struct ai_sentinel_event *event;

	if (!sentinel_state.config.enabled || !sentinel_state.config.track_file_ops)
		return 0;

	/* Only track writable operations to reduce overhead */
	if (!(mask & MAY_WRITE) && !(mask & MAY_APPEND))
		return 0;

	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (!event)
		return 0;

	event->type = AI_SENTINEL_EVENT_FILE_WRITE;
	event->pid = current->pid;
	event->tgid = current->tgid;
	event->uid = current->cred->uid.val;
	event->gid = current->cred->gid.val;
	event->timestamp = ktime_get_ns();
	memcpy(event->comm, current->comm, TASK_COMM_LEN);
	event->data.file.flags = file->f_flags;
	event->data.file.mode = file->f_inode->i_mode;

	/* Get file path */
	if (file->f_path.dentry) {
		char *path = event->data.file.path;
		char *tmp = dentry_path_raw(file->f_path.dentry,
					    path, PATH_MAX);
		if (IS_ERR(tmp))
			path[0] = '\0';
		else if (tmp != path)
			memmove(path, tmp, strlen(tmp) + 1);
	}

	event->severity = ai_sentinel_calculate_severity(event);

	/* Log significant file operations */
	if (sentinel_state.config.log_all_events ||
	    event->severity >= AI_SENTINEL_SEV_MEDIUM) {
		ai_sentinel_event_queue(event);
	} else {
		kfree(event);
	}

	return 0;
}

/**
 * ai_sentinel_socket_connect - Monitor outgoing connections
 * @sock: Socket being connected
 * @addr: Destination address
 * @addr_len: Address length
 *
 * Called when a socket is connecting to a remote endpoint.
 * Key for detecting C2 beacons and data exfiltration.
 */
int ai_sentinel_socket_connect(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct ai_sentinel_event *event;
	struct sockaddr_in *addr_in;

	if (!sentinel_state.config.enabled || !sentinel_state.config.track_net_ops)
		return 0;

	/* Only track IPv4/IPv6 */
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		return 0;

	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (!event)
		return 0;

	event->type = AI_SENTINEL_EVENT_SOCKET_CONNECT;
	event->pid = current->pid;
	event->tgid = current->tgid;
	event->uid = current->cred->uid.val;
	event->gid = current->cred->gid.val;
	event->timestamp = ktime_get_ns();
	memcpy(event->comm, current->comm, TASK_COMM_LEN);

	/* Extract connection details */
	addr_in = (struct sockaddr_in *)addr;
	event->data.socket.family = addr->sa_family;
	event->data.socket.protocol = sock->sk->sk_protocol;
	event->data.socket.dport = addr_in->sin_port;
	event->data.socket.daddr = addr_in->sin_addr.s_addr;

	event->severity = ai_sentinel_calculate_severity(event);

	/* Log connection attempts */
	ai_sentinel_event_queue(event);

	/* Check enforce mode for critical events */
	if (sentinel_state.config.enforce_mode &&
	    event->severity == AI_SENTINEL_SEV_CRITICAL) {
		pr_warn("AI-Sentinel: Blocking suspicious connection from %s\n",
			event->comm);
		kfree(event);
		return -ECONNREFUSED;
	}

	return 0;
}

/**
 * ai_sentinel_socket_bind - Monitor socket binds
 * @sock: Socket being bound
 * @addr: Address to bind to
 * @addr_len: Address length
 *
 * Called when a socket binds to a local port.
 * Useful for detecting malicious services.
 */
int ai_sentinel_socket_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct ai_sentinel_event *event;
	struct sockaddr_in *addr_in;

	if (!sentinel_state.config.enabled || !sentinel_state.config.track_net_ops)
		return 0;

	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		return 0;

	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (!event)
		return 0;

	event->type = AI_SENTINEL_EVENT_SOCKET_BIND;
	event->pid = current->pid;
	event->tgid = current->tgid;
	event->uid = current->cred->uid.val;
	event->gid = current->cred->gid.val;
	event->timestamp = ktime_get_ns();
	memcpy(event->comm, current->comm, TASK_COMM_LEN);

	addr_in = (struct sockaddr_in *)addr;
	event->data.socket.family = addr->sa_family;
	event->data.socket.protocol = sock->sk->sk_protocol;
	event->data.socket.sport = addr_in->sin_port;

	event->severity = AI_SENTINEL_SEV_LOW;

	ai_sentinel_event_queue(event);

	return 0;
}

/**
 * ai_sentinel_task_fix_setuid - Monitor privilege escalation
 * @new: New credentials
 * @old: Old credentials
 *
 * Called when a process changes its UID (setuid, etc.)
 * Critical for detecting privilege escalation attempts.
 */
int ai_sentinel_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	struct ai_sentinel_event *event;

	if (!sentinel_state.config.enabled)
		return 0;

	/* Check if UID is actually changing */
	if (new->uid.val == old->uid.val)
		return 0;

	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (!event)
		return 0;

	event->type = AI_SENTINEL_EVENT_PRIV_ESCALATE;
	event->pid = current->pid;
	event->tgid = current->tgid;
	event->uid = old->uid.val;
	event->gid = old->gid.val;
	event->timestamp = ktime_get_ns();
	memcpy(event->comm, current->comm, TASK_COMM_LEN);

	event->data.privilege.ruid = old->uid.val;
	event->data.privilege.euid = new->uid.val;

	event->severity = ai_sentinel_calculate_severity(event);

	/* Always log privilege changes */
	ai_sentinel_event_queue(event);

	/* Log to kernel */
	pr_info("AI-Sentinel: Privilege escalation - %s: %d -> %d\n",
		event->comm, old->uid.val, new->uid.val);

	/* Reduce trust score */
	ai_sentinel_proc_update_score(current->pid, -20);

	return 0;
}

/**
 * ai_sentinel_file_mmap - Monitor memory mappings
 * @file: File being mapped (can be NULL for anonymous mappings)
 * @reqprot: Protection requested by user
 * @prot: Protection after accounting for file permissions
 * @flags: Mapping flags
 *
 * Called when a process creates a memory mapping.
 * Important for detecting shellcode injection and W+X mappings.
 */
