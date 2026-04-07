// SPDX-License-Identifier: GPL-2.0
/*
 * AI-Sentinel LSM - Process Tracking
 *
 * Copyright (c) 2025 AEGIS-OS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>

#include "ai_sentinel.h"

/* External global state */
extern struct ai_sentinel_state sentinel_state;

/**
 * ai_sentinel_proc_add - Add a process to the tracking list
 * @pid: Process ID
 * @task: Task struct
 *
 * Creates a new process tracking entry or updates existing.
 */
int ai_sentinel_proc_add(pid_t pid, struct task_struct *task)
{
	struct ai_sentinel_proc *proc, *existing;
	unsigned long flags;
	struct mm_struct *mm;
	struct file *exe_file;

	if (!sentinel_state.config.track_processes)
		return 0;

	/* Check if process already exists */
	existing = ai_sentinel_proc_find(pid);
	if (existing) {
		/* Update last activity time */
		existing->last_activity = ktime_get_ns();
		return 0;
	}

	/* Allocate new process entry */
	proc = kzalloc(sizeof(*proc), GFP_ATOMIC);
	if (!proc)
		return -ENOMEM;

	/* Initialize process tracking data */
	proc->pid = pid;
	proc->ppid = task->real_parent->pid;
	proc->uid = task->cred->uid.val;
	proc->gid = task->cred->gid.val;
	proc->trust_score = sentinel_state.config.default_trust_score;
	proc->flags = 0;
	proc->start_time = ktime_get_ns();
	proc->last_activity = proc->start_time;
	proc->syscall_count = 0;
	proc->file_ops = 0;
	proc->net_ops = 0;

	memcpy(proc->comm, task->comm, TASK_COMM_LEN);

	/* Get executable path */
	mm = get_task_mm(task);
	if (mm) {
		down_read(&mm->mmap_lock);
		exe_file = mm->exe_file;
		if (exe_file) {
			char *path = proc->exe_path;
			char *tmp;
			get_file(exe_file);
			tmp = dentry_path_raw(exe_file->f_path.dentry,
					 path, PATH_MAX);
			if (IS_ERR(tmp)) {
				path[0] = '\0';
			} else if (tmp != path) {
				size_t len = strlen(tmp);
				if (len >= PATH_MAX) {
					path[0] = '\0';
				} else {
					memmove(path, tmp, len + 1);
				}
			}
			fput(exe_file);
		}
		up_read(&mm->mmap_lock);
		mmput(mm);
	}

	/* Add to process list */
	spin_lock_irqsave(&sentinel_state.proc_lock, flags);

	/* Double-check list size */
	if (atomic_read(&sentinel_state.event_count) > AI_SENTINEL_MAX_PROCS) {
		spin_unlock_irqrestore(&sentinel_state.proc_lock, flags);
		kfree(proc);
		pr_warn("AI-Sentinel: Process tracking limit reached\n");
		return -ENOSPC;
	}

	list_add_rcu(&proc->list, &sentinel_state.proc_list);
	spin_unlock_irqrestore(&sentinel_state.proc_lock, flags);

	pr_debug("AI-Sentinel: Tracking process %s (pid=%d, score=%d)\n",
		 proc->comm, proc->pid, proc->trust_score);

	return 0;
}

/**
 * ai_sentinel_proc_remove - Remove a process from tracking
 * @pid: Process ID to remove
 */
void ai_sentinel_proc_remove(pid_t pid)
{
	struct ai_sentinel_proc *proc, *tmp;
	struct ai_sentinel_proc *victim = NULL;
	unsigned long flags;

	rcu_read_lock();
	list_for_each_entry_rcu(proc, &sentinel_state.proc_list, list) {
		if (proc->pid == pid) {
			victim = proc;
			break;
		}
	}
	rcu_read_unlock();

	if (victim) {
		spin_lock_irqsave(&sentinel_state.proc_lock, flags);
		list_del_rcu(&victim->list);
		spin_unlock_irqrestore(&sentinel_state.proc_lock, flags);
		synchronize_rcu();
		pr_debug("AI-Sentinel: Removed process %s (pid=%d)\n",
			 victim->comm, victim->pid);
		kfree(victim);
	}
}

/**
 * ai_sentinel_proc_find - Find a process in the tracking list
 * @pid: Process ID to find
 *
 * Returns process entry under RCU lock (caller must hold RCU or take reference).
 */
struct ai_sentinel_proc *ai_sentinel_proc_find(pid_t pid)
{
	struct ai_sentinel_proc *proc;

	rcu_read_lock();
	list_for_each_entry_rcu(proc, &sentinel_state.proc_list, list) {
		if (proc->pid == pid) {
			rcu_read_unlock();
			return proc;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/**
 * ai_sentinel_proc_update_score - Update process trust score
 * @pid: Process ID
 * @delta: Score change (can be positive or negative)
 */
void ai_sentinel_proc_update_score(pid_t pid, int delta)
{
	struct ai_sentinel_proc *proc;
	unsigned long flags;
	bool clamped = false;

	spin_lock_irqsave(&sentinel_state.proc_lock, flags);
	list_for_each_entry(proc, &sentinel_state.proc_list, list) {
		if (proc->pid == pid) {
			int old_score = proc->trust_score;
			proc->trust_score += delta;

			/* Clamp to valid range */
			if (proc->trust_score > AI_SENTINEL_TRUST_MAX) {
				proc->trust_score = AI_SENTINEL_TRUST_MAX;
				clamped = true;
			} else if (proc->trust_score < AI_SENTINEL_TRUST_MIN) {
				proc->trust_score = AI_SENTINEL_TRUST_MIN;
				clamped = true;
			}

			if (delta != 0) {
				pr_debug("AI-Sentinel: %s score %d: %d -> %d%s\n",
					 proc->comm, proc->pid, old_score,
					 proc->trust_score,
					 clamped ? " (clamped)" : "");
			}

			/* Update last activity */
			proc->last_activity = ktime_get_ns();
			break;
		}
	}
	spin_unlock_irqrestore(&sentinel_state.proc_lock, flags);
}

/**
 * ai_sentinel_proc_get_score - Get process trust score
 * @pid: Process ID
 *
 * Returns the current trust score for a process.
 */
int ai_sentinel_proc_get_score(pid_t pid)
{
	struct ai_sentinel_proc *proc;
	int score = sentinel_state.config.default_trust_score;

	rcu_read_lock();
	proc = ai_sentinel_proc_find(pid);
	if (proc)
		score = proc->trust_score;
	rcu_read_unlock();

	return score;
}

/**
 * ai_sentinel_proc_get_stats - Get process statistics
 * @pid: Process ID
 * @stats: Output structure for statistics
 *
 * Fills in statistics about a tracked process.
 */
int ai_sentinel_proc_get_stats(pid_t pid, struct ai_sentinel_proc *stats)
{
	struct ai_sentinel_proc *proc;

	rcu_read_lock();
	proc = ai_sentinel_proc_find(pid);
	if (!proc) {
		rcu_read_unlock();
		return -ENOENT;
	}

	memcpy(stats, proc, sizeof(*proc));
	rcu_read_unlock();

	return 0;
}

/**
 * ai_sentinel_proc_list_all - List all tracked processes
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Dumps process list to buffer (for debugging/proc interface).
 */
int ai_sentinel_proc_list_all(char *buf, size_t size)
{
	struct ai_sentinel_proc *proc;
	int len = 0;

	len += scnprintf(buf + len, size - len,
			 "PID\tPPID\tUID\tScore\tComm\t\tExe\n");
	len += scnprintf(buf + len, size - len,
			 "------------------------------------------------\n");

	rcu_read_lock();
	list_for_each_entry_rcu(proc, &sentinel_state.proc_list, list) {
		len += scnprintf(buf + len, size - len,
				 "%d\t%d\t%d\t%d\t%s\t%s\n",
				 proc->pid, proc->ppid, proc->uid,
				 proc->trust_score, proc->comm, proc->exe_path);
	}
	rcu_read_unlock();

	return len;
}

/**
 * ai_sentinel_proc_cleanup_old - Remove old process entries
 * @max_age_ns: Maximum age in nanoseconds
 *
 * Cleans up process entries that are older than max_age_ns.
 * Useful for removing entries where task_free wasn't called.
 */
void ai_sentinel_proc_cleanup_old(u64 max_age_ns)
{
	struct ai_sentinel_proc *proc, *tmp;
	u64 now = ktime_get_ns();
	unsigned long flags;

	spin_lock_irqsave(&sentinel_state.proc_lock, flags);
	list_for_each_entry_safe(proc, tmp, &sentinel_state.proc_list, list) {
		if (now - proc->last_activity > max_age_ns) {
			pr_debug("AI-Sentinel: Cleaning up old process %s (pid=%d)\n",
				 proc->comm, proc->pid);
			list_del_rcu(&proc->list);
			kfree_rcu(proc, rcu);
		}
	}
	spin_unlock_irqrestore(&sentinel_state.proc_lock, flags);
}
