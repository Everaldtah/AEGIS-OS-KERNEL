// SPDX-License-Identifier: GPL-2.0
/*
 * AI-Sentinel LSM - Sysfs Interface
 *
 * Copyright (c) 2025 AEGIS-OS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>

#include "ai_sentinel.h"

/* External global state */
extern struct ai_sentinel_state sentinel_state;

/* Kernel object */
static struct kobject *ai_sentinel_kobj;

/* Sysfs attribute: enabled */
static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%d\n", sentinel_state.config.enabled);
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	sentinel_state.config.enabled = !!val;

	pr_info("AI-Sentinel: %s\n", val ? "Enabled" : "Disabled");

	return count;
}

/* Sysfs attribute: enforce_mode */
static ssize_t enforce_mode_show(struct kobject *kobj, struct kobj_attribute *attr,
				 char *buf)
{
	return sprintf(buf, "%d\n", sentinel_state.config.enforce_mode);
}

static ssize_t enforce_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	sentinel_state.config.enforce_mode = !!val;

	pr_info("AI-Sentinel: Mode changed to %s\n",
		val ? "ENFORCE" : "MONITOR");

	return count;
}

/* Sysfs attribute: default_trust_score */
static ssize_t default_trust_score_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", sentinel_state.config.default_trust_score);
}

static ssize_t default_trust_score_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	int val;

	if (kstrtoint(buf, 10, &val))
		return -EINVAL;

	if (val < AI_SENTINEL_TRUST_MIN || val > AI_SENTINEL_TRUST_MAX)
		return -EINVAL;

	sentinel_state.config.default_trust_score = val;

	return count;
}

/* Sysfs attribute: version */
static ssize_t version_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	return sprintf(buf, "%s\n", AI_SENTINEL_VERSION);
}

/* Sysfs attribute: tracked_processes */
static ssize_t tracked_processes_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct ai_sentinel_proc *proc;
	int count = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(proc, &sentinel_state.proc_list, list) {
		count++;
	}
	rcu_read_unlock();

	return sprintf(buf, "%d\n", count);
}

/* Sysfs attribute: pending_events */
static ssize_t pending_events_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", atomic_read(&sentinel_state.event_count));
}

/* Sysfs attribute: process_list (read-only) */
static ssize_t process_list_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	return ai_sentinel_proc_list_all(buf, PAGE_SIZE);
}

/* Attribute structures */
static struct kobj_attribute enabled_attr =
	__ATTR(enabled, 0644, enabled_show, enabled_store);

static struct kobj_attribute enforce_mode_attr =
	__ATTR(enforce_mode, 0644, enforce_mode_show, enforce_mode_store);

static struct kobj_attribute default_trust_score_attr =
	__ATTR(default_trust_score, 0644, default_trust_score_show,
	       default_trust_score_store);

static struct kobj_attribute version_attr =
	__ATTR(version, 0444, version_show, NULL);

static struct kobj_attribute tracked_processes_attr =
	__ATTR(tracked_processes, 0444, tracked_processes_show, NULL);

static struct kobj_attribute pending_events_attr =
	__ATTR(pending_events, 0444, pending_events_show, NULL);

static struct kobj_attribute process_list_attr =
	__ATTR(process_list, 0444, process_list_show, NULL);

/* Array of attributes */
static struct attribute *ai_sentinel_attrs[] = {
	&enabled_attr.attr,
	&enforce_mode_attr.attr,
	&default_trust_score_attr.attr,
	&version_attr.attr,
	&tracked_processes_attr.attr,
	&pending_events_attr.attr,
	&process_list_attr.attr,
	NULL,
};

/* Attribute group */
static struct attribute_group ai_sentinel_attr_group = {
	.attrs = ai_sentinel_attrs,
};

/**
 * ai_sentinel_sysfs_init - Initialize sysfs interface
 */
int ai_sentinel_sysfs_init(void)
{
	int ret;

	/* Create kobject under /sys/kernel/ */
	ai_sentinel_kobj = kobject_create_and_add("ai_sentinel", kernel_kobj);
	if (!ai_sentinel_kobj) {
		pr_err("AI-Sentinel: Failed to create kobject\n");
		return -ENOMEM;
	}

	/* Create sysfs files */
	ret = sysfs_create_group(ai_sentinel_kobj, &ai_sentinel_attr_group);
	if (ret) {
		pr_err("AI-Sentinel: Failed to create sysfs group: %d\n", ret);
		kobject_put(ai_sentinel_kobj);
		return ret;
	}

	pr_info("AI-Sentinel: Sysfs interface registered\n");

	return 0;
}

/**
 * ai_sentinel_sysfs_exit - Cleanup sysfs interface
 */
void ai_sentinel_sysfs_exit(void)
{
	if (ai_sentinel_kobj) {
		sysfs_remove_group(ai_sentinel_kobj, &ai_sentinel_attr_group);
		kobject_put(ai_sentinel_kobj);
		ai_sentinel_kobj = NULL;
	}

	pr_info("AI-Sentinel: Sysfs interface unregistered\n");
}
