// SPDX-License-Identifier: GPL-2.0
/*
 * AI-Sentinel LSM - Netlink Communication
 *
 * Copyright (c) 2025 AEGIS-OS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "ai_sentinel.h"

/* External global state */
extern struct ai_sentinel_state sentinel_state;

/* Netlink socket */
static struct sock *ai_sentinel_nl_sock = NULL;

/* Netlink message attributes */
enum {
	AI_SENTINEL_ATTR_UNSPEC,
	AI_SENTINEL_ATTR_TYPE,
	AI_SENTINEL_ATTR_SEVERITY,
	AI_SENTINEL_ATTR_PID,
	AI_SENTINEL_ATTR_UID,
	AI_SENTINEL_ATTR_COMM,
	AI_SENTINEL_ATTR_TIMESTAMP,
	AI_SENTINEL_ATTR_DATA,
	__AI_SENTINEL_ATTR_MAX
};

#define AI_SENTINEL_ATTR_MAX (__AI_SENTINEL_ATTR_MAX - 1)

/* Policy for netlink attributes */
static const struct nla_policy ai_sentinel_attr_policy[__AI_SENTINEL_ATTR_MAX + 1] = {
	[AI_SENTINEL_ATTR_TYPE] = { .type = NLA_U32 },
	[AI_SENTINEL_ATTR_SEVERITY] = { .type = NLA_U32 },
	[AI_SENTINEL_ATTR_PID] = { .type = NLA_U32 },
	[AI_SENTINEL_ATTR_UID] = { .type = NLA_U32 },
	[AI_SENTINEL_ATTR_COMM] = { .type = NLA_STRING, .len = TASK_COMM_LEN },
	[AI_SENTINEL_ATTR_TIMESTAMP] = { .type = NLA_U64 },
	[AI_SENTINEL_ATTR_DATA] = { .type = NLA_NESTED },
};

/**
 * ai_sentinel_netlink_init - Initialize netlink socket
 */
int ai_sentinel_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = ai_sentinel_netlink_recv,
		.groups = AI_SENTINEL_NETLINK_GROUP,
	};

	ai_sentinel_nl_sock = netlink_kernel_create(&init_net,
						    AI_SENTINEL_NETLINK_FAMILY,
						    &cfg);
	if (!ai_sentinel_nl_sock) {
		pr_err("AI-Sentinel: Failed to create netlink socket\n");
		return -ENOMEM;
	}

	pr_info("AI-Sentinel: Netlink socket initialized (family=%d)\n",
		AI_SENTINEL_NETLINK_FAMILY);

	return 0;
}

/**
 * ai_sentinel_netlink_exit - Cleanup netlink socket
 */
void ai_sentinel_netlink_exit(void)
{
	if (ai_sentinel_nl_sock) {
		netlink_kernel_release(ai_sentinel_nl_sock);
		ai_sentinel_nl_sock = NULL;
	}
}

/**
 * ai_sentinel_event_send - Send event to userspace
 * @event: Event to send
 *
 * Sends security event to userspace AI runtime via netlink.
 */
void ai_sentinel_event_send(struct ai_sentinel_event *event)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	void *data;
	int ret;
	int size = nla_total_size(sizeof(event->data));

	if (!ai_sentinel_nl_sock) {
		kfree(event);
		return;
	}

	/* Allocate skb with enough space */
	skb = nlmsg_new(size, GFP_ATOMIC);
	if (!skb) {
		pr_err("AI-Sentinel: Failed to allocate netlink message\n");
		kfree(event);
		return;
	}

	/* Create netlink message header */
	nlh = nlmsg_put(skb, 0, 0, AI_SENTINEL_NLMSG_MIN_TYPE, size, 0);
	if (!nlh) {
		pr_err("AI-Sentinel: Failed to put netlink header\n");
		kfree_skb(skb);
		kfree(event);
		return;
	}

	/* Add event data */
	data = nla_nest_start(skb, AI_SENTINEL_ATTR_DATA);
	if (!data) {
		pr_err("AI-Sentinel: Failed to start nest\n");
		kfree_skb(skb);
		kfree(event);
		return;
	}

	/* Add event type */
	ret = nla_put_u32(skb, AI_SENTINEL_ATTR_TYPE, event->type);
	if (ret) {
		pr_err("AI-Sentinel: Failed to put event type\n");
		goto nla_put_failure;
	}

	/* Add severity */
	ret = nla_put_u32(skb, AI_SENTINEL_ATTR_SEVERITY, event->severity);
	if (ret) {
		pr_err("AI-Sentinel: Failed to put severity\n");
		goto nla_put_failure;
	}

	/* Add PID */
	ret = nla_put_u32(skb, AI_SENTINEL_ATTR_PID, event->pid);
	if (ret) {
		pr_err("AI-Sentinel: Failed to put PID\n");
		goto nla_put_failure;
	}

	/* Add UID */
	ret = nla_put_u32(skb, AI_SENTINEL_ATTR_UID, event->uid);
	if (ret) {
		pr_err("AI-Sentinel: Failed to put UID\n");
		goto nla_put_failure;
	}

	/* Add command name */
	ret = nla_put_string(skb, AI_SENTINEL_ATTR_COMM, event->comm);
	if (ret) {
		pr_err("AI-Sentinel: Failed to put comm\n");
		goto nla_put_failure;
	}

	/* Add timestamp */
	ret = nla_put_u64_64bit(skb, AI_SENTINEL_ATTR_TIMESTAMP, event->timestamp, 0);
	if (ret) {
		pr_err("AI-Sentinel: Failed to put timestamp\n");
		goto nla_put_failure;
	}

	/* Add type-specific data */
	switch (event->type) {
	case AI_SENTINEL_EVENT_FILE_OPEN:
	case AI_SENTINEL_EVENT_FILE_WRITE:
		ret = nla_put_string(skb, AI_SENTINEL_ATTR_DATA + 1,
				    event->data.file.path);
		break;
	case AI_SENTINEL_EVENT_SOCKET_CONNECT:
	case AI_SENTINEL_EVENT_SOCKET_BIND:
		/* Network info already included */
		break;
	case AI_SENTINEL_EVENT_PRIV_ESCALATE:
		ret = nla_put_u32(skb, AI_SENTINEL_ATTR_DATA + 2,
				 event->data.privilege.euid);
		break;
	case AI_SENTINEL_EVENT_MMAP_EXEC:
		ret = nla_put_u64_64bit(skb, AI_SENTINEL_ATTR_DATA + 3,
				       event->data.mmap.addr, 0);
		break;
	default:
		break;
	}

	if (ret) {
		pr_err("AI-Sentinel: Failed to put event data\n");
		goto nla_put_failure;
	}

	nla_nest_end(skb, data);

	/* Send to userspace multicast group */
	ret = nlmsg_multicast(ai_sentinel_nl_sock, skb, 0,
			     AI_SENTINEL_NETLINK_GROUP, GFP_ATOMIC);
	if (ret == -ESRCH) {
		/* No userspace listeners - silently drop */
		kfree_skb(skb);
	} else if (ret < 0) {
		pr_debug("AI-Sentinel: Failed to send netlink message: %d\n", ret);
		kfree_skb(skb);
	}

	kfree(event);
	return;

nla_put_failure:
	nla_nest_cancel(skb, data);
	kfree_skb(skb);
	kfree(event);
}

/**
 * ai_sentinel_event_queue - Queue event for processing
 * @event: Event to queue
 */
int ai_sentinel_event_queue(struct ai_sentinel_event *event)
{
	unsigned long flags;

	if (!event)
		return -EINVAL;

	spin_lock_irqsave(&sentinel_state.event_lock, flags);
	list_add_tail(&event->list, &sentinel_state.event_queue);
	atomic_inc(&sentinel_state.event_count);
	spin_unlock_irqrestore(&sentinel_state.event_lock, flags);

	/* Trigger immediate flush for high-severity events */
	if (event->severity >= AI_SENTINEL_SEV_HIGH) {
		queue_work(sentinel_state.event_wq, &sentinel_state.event_work);
	}

	return 0;
}

/**
 * ai_sentinel_event_flush - Flush event queue to userspace
 * @work: Work struct
 *
 * Workqueue callback that processes queued events and sends them
 * to userspace via netlink.
 */
void ai_sentinel_event_flush(struct work_struct *work)
{
	struct ai_sentinel_event *event, *tmp;
	LIST_HEAD(local_list);
	unsigned long flags;

	/* Move events to local list */
	spin_lock_irqsave(&sentinel_state.event_lock, flags);
	list_splice_init(&sentinel_state.event_queue, &local_list);
	spin_unlock_irqrestore(&sentinel_state.event_lock, flags);

	/* Process events */
	list_for_each_entry_safe(event, tmp, &local_list, list) {
		list_del(&event->list);
		atomic_dec(&sentinel_state.event_count);

		/* Send to userspace */
		ai_sentinel_event_send(event);
	}
}

/**
 * ai_sentinel_event_timer_callback - Periodic event flush
 * @timer: Timer list
 *
 * Called periodically to flush pending events even if no
 * high-severity events have occurred.
 */
void ai_sentinel_event_timer_callback(struct timer_list *timer)
{
	/* Flush pending events */
	queue_work(sentinel_state.event_wq, &sentinel_state.event_work);

	/* Reschedule timer */
	mod_timer(&sentinel_state.event_timer, jiffies + HZ / 10);
}

/**
 * ai_sentinel_netlink_recv - Receive commands from userspace
 * @skb: Socket buffer
 *
 * Receives control commands from userspace AI runtime.
 * Commands can include:
 * - Allow/block/quarantine decisions
 * - Trust score adjustments
 * - Configuration changes
 */
void ai_sentinel_netlink_recv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct nlattr *attrs[__AI_SENTINEL_ATTR_MAX + 1];
	int ret;

	/* Parse message */
	nlh = nlmsg_hdr(skb);
	ret = nlmsg_parse(nlh, 0, attrs, AI_SENTINEL_ATTR_MAX, ai_sentinel_attr_policy, NULL);
	if (ret) {
		pr_err("AI-Sentinel: Failed to parse netlink message\n");
		return;
	}

	/* Handle commands from userspace */
	if (attrs[AI_SENTINEL_ATTR_PID]) {
		pid_t pid = nla_get_u32(attrs[AI_SENTINEL_ATTR_PID]);

		/* Example: Adjust trust score based on AI analysis */
		if (attrs[AI_SENTINEL_ATTR_TYPE]) {
			u32 type = nla_get_u32(attrs[AI_SENTINEL_ATTR_TYPE]);

			switch (type) {
			case AI_SENTINEL_DECISION_ALLOW:
				ai_sentinel_proc_update_score(pid, 5);
				break;
			case AI_SENTINEL_DECISION_BLOCK:
				ai_sentinel_proc_update_score(pid, -30);
				break;
			case AI_SENTINEL_DECISION_QUARANTINE:
				ai_sentinel_proc_update_score(pid, -50);
				break;
			case AI_SENTINEL_DECISION_KILL:
				/* Kill process */
				ai_sentinel_proc_update_score(pid, -100);
				/* TODO: Send kill signal */
				break;
			}
		}
	}

	/* Configuration updates */
	/* TODO: Implement dynamic configuration changes */
}
