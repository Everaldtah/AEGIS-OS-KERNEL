/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AI-Sentinel LSM - AEGIS-OS
 * Linux Security Module for real-time behavioral analysis
 *
 * Copyright (c) 2025 AEGIS-OS Project
 */

#ifndef _AI_SENTINEL_H
#define _AI_SENTINEL_H

#include <linux/security.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/mm.h>
#include <linux/mman.h>

/* Version information */
#define AI_SENTINEL_VERSION "1.0.0"
#define AI_SENTINEL_NAME "ai_sentinel"

/* Maximum number of tracked processes */
#define AI_SENTINEL_MAX_PROCS 4096

/* Trust score bounds */
#define AI_SENTINEL_TRUST_MIN 0
#define AI_SENTINEL_TRUST_MAX 100
#define AI_SENTINEL_TRUST_DEFAULT 75

/* Netlink configuration */
#define AI_SENTINEL_NETLINK_FAMILY 31
#define AI_SENTINEL_NETLINK_GROUP 1
#define AI_SENTINEL_NLMSG_MIN_TYPE 0x10

/* Event types */
enum ai_sentinel_event_type {
	AI_SENTINEL_EVENT_EXEC = 0,
	AI_SENTINEL_EVENT_EXIT,
	AI_SENTINEL_EVENT_FORK,
	AI_SENTINEL_EVENT_FILE_OPEN,
	AI_SENTINEL_EVENT_FILE_WRITE,
	AI_SENTINEL_EVENT_SOCKET_CONNECT,
	AI_SENTINEL_EVENT_SOCKET_BIND,
	AI_SENTINEL_EVENT_PRIV_ESCALATE,
	AI_SENTINEL_EVENT_MMAP_EXEC,
	AI_SENTINEL_EVENT_PTRACE,
	AI_SENTINEL_EVENT_MAX
};

/* Event severity */
enum ai_sentinel_severity {
	AI_SENTINEL_SEV_INFO = 0,
	AI_SENTINEL_SEV_LOW,
	AI_SENTINEL_SEV_MEDIUM,
	AI_SENTINEL_SEV_HIGH,
	AI_SENTINEL_SEV_CRITICAL
};

/* Decision types from userspace AI */
enum ai_sentinel_decision {
	AI_SENTINEL_DECISION_ALLOW = 0,
	AI_SENTINEL_DECISION_BLOCK,
	AI_SENTINEL_DECISION_QUARANTINE,
	AI_SENTINEL_DECISION_KILL
};

/* Process tracking structure */
struct ai_sentinel_proc {
	struct list_head list;
	struct rcu_head rcu;
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	gid_t gid;
	int trust_score;
	unsigned long flags;
	char comm[TASK_COMM_LEN];
	char exe_path[PATH_MAX];
	/* Statistics */
	unsigned long syscall_count;
	unsigned long file_ops;
	unsigned long net_ops;
	/* Timestamps */
	u64 start_time;
	u64 last_activity;
};

/* Event notification structure */
struct ai_sentinel_event {
	struct list_head list;
	enum ai_sentinel_event_type type;
	enum ai_sentinel_severity severity;
	pid_t pid;
	pid_t tgid;
	uid_t uid;
	gid_t gid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	union {
		struct {
			char path[PATH_MAX];
			int flags;
			mode_t mode;
		} file;
		struct {
			__be16 saddr;
			__be16 daddr;
			u16 sport;
			u16 dport;
			u16 family;
			u8 protocol;
		} socket;
		struct {
			uid_t ruid;
			uid_t euid;
		} privilege;
		struct {
			unsigned long addr;
			unsigned long size;
			int prot;
		} mmap;
	} data;
};

/* Configuration structure */
struct ai_sentinel_config {
	bool enabled;
	bool enforce_mode;
	bool log_all_events;
	int default_trust_score;
	bool track_processes;
	bool track_file_ops;
	bool track_net_ops;
	bool detect_anomalies;
};

/* Global state */
struct ai_sentinel_state {
	struct list_head proc_list;
	spinlock_t proc_lock;
	struct list_head event_queue;
	spinlock_t event_lock;
	struct sock *nl_sock;
	struct timer_list event_timer;
	struct workqueue_struct *event_wq;
	struct work_struct event_work;
	struct ai_sentinel_config config;
	atomic_t event_count;
};

/* Function declarations */

/* Main module */
int __init ai_sentinel_init(void);
void __exit ai_sentinel_exit(void);

/* Process tracking */
int ai_sentinel_proc_add(pid_t pid, struct task_struct *task);
void ai_sentinel_proc_remove(pid_t pid);
struct ai_sentinel_proc *ai_sentinel_proc_find(pid_t pid);
void ai_sentinel_proc_update_score(pid_t pid, int delta);
int ai_sentinel_proc_get_score(pid_t pid);
int ai_sentinel_proc_get_stats(pid_t pid, struct ai_sentinel_proc *stats);
int ai_sentinel_proc_list_all(char *buf, size_t size);
void ai_sentinel_proc_cleanup_old(u64 max_age_ns);

/* Event handling */
int ai_sentinel_event_queue(struct ai_sentinel_event *event);
void ai_sentinel_event_flush(struct work_struct *work);
void ai_sentinel_event_send(struct ai_sentinel_event *event);
void ai_sentinel_event_timer_callback(struct timer_list *timer);

/* Hooks */
int ai_sentinel_bprm_check_security(struct linux_binprm *bprm);
void ai_sentinel_task_free(struct task_struct *task);
int ai_sentinel_file_permission(struct file *file, int mask);
int ai_sentinel_socket_connect(struct socket *sock, struct sockaddr *addr, int addr_len);
int ai_sentinel_socket_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
int ai_sentinel_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
int ai_sentinel_ptrace_access_check(struct task_struct *child, unsigned int mode);

/* Netlink */
int ai_sentinel_netlink_init(void);
void ai_sentinel_netlink_exit(void);
void ai_sentinel_netlink_recv(struct sk_buff *skb);

/* Sysfs */
int ai_sentinel_sysfs_init(void);
void ai_sentinel_sysfs_exit(void);

/* Utility functions */
enum ai_sentinel_severity ai_sentinel_calculate_severity(struct ai_sentinel_event *event);
char *ai_sentinel_event_type_str(enum ai_sentinel_event_type type);
char *ai_sentinel_severity_str(enum ai_sentinel_severity sev);

#endif /* _AI_SENTINEL_H */
