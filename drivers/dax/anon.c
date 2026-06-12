// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2026 Meta Technologies Inc. All rights reserved. */

/*
 * Anondax is a control surface for device memory to opt into mm/ services.
 *
 * Binding the driver creates an unplugged device.
 * Writing the "hotplug" sysfs attribute hotplugs memory onto a private node.
 *
 * mapping the /dev/daxN.N character device provides an ordinary ANONYMOUS
 * mapping bound to the private node via an MPOL_F_PRIVATE mempolicy.
 *
 * The normal anonymous fault and swap-in paths then allocate every folio
 * from the private node through that policy and install it as a normal
 * anonymous (LRU + rmap) folio - no custom fault handler.
 *
 * The result is ordinary, struct-page, allocator-managed memory pinned to an
 * isolated node and mapped into a real process.
 *
 * Capability bits provide pre-hotplug control over what services (reclaim,
 * demotion, numa balancing) are enabled for this memory.
 */

#include <linux/memory.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mempolicy.h>
#include <linux/mutex.h>
#include <linux/memory_hotplug.h>
#include <linux/node_private.h>
#include <linux/sched/mm.h>
#include <linux/string_helpers.h>
#include "dax-private.h"
#include "bus.h"

static const char *anon_dax_name;

/* Hotplug state, driven by the "hotplug" sysfs attribute. */
enum anon_dax_state {
	ANON_DAX_UNPLUGGED,
	ANON_DAX_MOVABLE,
	ANON_DAX_KERNEL,
};

static const char * const anon_dax_state_name[] = {
	[ANON_DAX_UNPLUGGED]	= "unplugged",
	[ANON_DAX_MOVABLE]	= "online_movable",
	[ANON_DAX_KERNEL]	= "online_kernel",
};

/**
 * struct anon_dax_data - per-device state for an anondax instance
 * @lock: serializes hotplug transitions and config writes
 * @state: current hotplug state (enum anon_dax_state)
 * @caps: NODE_PRIVATE_CAP_* service opt-ins to apply at hotplug; writable via
 *	  the per-service sysfs toggles only while unplugged
 * @mgid: memory group id the ranges were registered under
 * @numa_node: the private NUMA node backing this device
 * @policy: device-lifetime MPOL_BIND|MPOL_F_PRIVATE policy bound to @numa_node,
 *	handed out by ->get_policy so faults (including swap-in) land on the
 *	node without a userspace mbind(); NULL until first onlined
 * @np: driver-owned node_private; must outlive the registration, so it lives
 *	here for the device's lifetime
 * @res: per-range reserved iomem resources (released on remove)
 */
struct anon_dax_data {
	struct mutex lock;
	int state;
	unsigned long caps;
	int mgid;
	int numa_node;
	struct mempolicy *policy;
	struct node_private np;
	struct resource *res[];
};

static int anon_dax_range(struct dev_dax *dev_dax, int i, struct range *r)
{
	struct range *range = &dev_dax->ranges[i].range;

	*r = memory_block_aligned_range(range);
	if (r->start >= r->end) {
		*r = *range;
		return -ENOSPC;
	}
	return 0;
}

/*
 * Reserve and online every (memory-block-aligned) range as N_MEMORY_PRIVATE
 * memory in @online_type's zone.  Returns the number of ranges onlined, or a
 * negative errno if nothing could be brought up.
 */
static int anon_dax_add(struct dev_dax *dev_dax, struct anon_dax_data *data,
			int online_type)
{
	struct device *dev = &dev_dax->dev;
	int i, rc, added = 0;

	/*
	 * Apply the configured service opt-ins to the node before it is
	 * registered, so the node carries them for its whole online lifetime.
	 */
	data->np.caps = data->caps;

	for (i = 0; i < dev_dax->nr_range; i++) {
		struct resource *res;
		struct range range;

		if (anon_dax_range(dev_dax, i, &range))
			continue;

		res = request_mem_region(range.start, range_len(&range),
					 anon_dax_name);
		if (!res) {
			dev_warn(dev, "mapping%d: %#llx-%#llx could not reserve\n",
				 i, range.start, range.end);
			if (added)
				continue;
			return -EBUSY;
		}
		/* Leave _BUSY clear so add_memory() can add a child resource. */
		res->flags = IORESOURCE_SYSTEM_RAM;
		data->res[i] = res;

		/*
		 * Re-registration of the same @np for each subsequent range is a
		 * no-op (single owner per node).
		 */
		rc = add_private_memory_driver_managed(data->mgid, range.start,
				range_len(&range), anon_dax_name, MHP_NID_IS_MGID,
				online_type, &data->np);
		if (rc) {
			dev_warn(dev, "mapping%d: %#llx-%#llx add failed: %d\n",
				 i, range.start, range.end, rc);
			remove_resource(res);
			kfree(res);
			data->res[i] = NULL;
			if (added)
				continue;
			return rc;
		}
		added++;
	}

	return added ? added : -ENOMEM;
}

#ifdef CONFIG_MEMORY_HOTREMOVE
static void anon_dax_release_resources(struct dev_dax *dev_dax,
				       struct anon_dax_data *data)
{
	int i;

	for (i = 0; i < dev_dax->nr_range; i++) {
		if (!data->res[i])
			continue;
		remove_resource(data->res[i]);
		kfree(data->res[i]);
		data->res[i] = NULL;
	}
}

/*
 * Offline and remove every onlined range.  offline_and_remove_memory_ranges()
 * also drops the node_private registration once the node is empty.  Fails (and
 * leaks) if any page is still in use - e.g. still faulted into a process - since
 * private-node memory cannot be migrated out.
 */
static int anon_dax_drop(struct dev_dax *dev_dax, struct anon_dax_data *data)
{
	struct device *dev = &dev_dax->dev;
	struct range *ranges;
	int i, nr_ranges = 0, rc;

	ranges = kmalloc_array(dev_dax->nr_range, sizeof(*ranges), GFP_KERNEL);
	if (!ranges)
		return -ENOMEM;

	for (i = 0; i < dev_dax->nr_range; i++) {
		struct range range;

		if (!data->res[i] || anon_dax_range(dev_dax, i, &range))
			continue;
		ranges[nr_ranges++] = range;
	}

	if (!nr_ranges) {
		kfree(ranges);
		return 0;
	}

	rc = offline_and_remove_memory_ranges(ranges, nr_ranges);
	kfree(ranges);
	if (rc) {
		dev_err(dev, "memory still in use, left online: %d\n", rc);
		return rc;
	}

	anon_dax_release_resources(dev_dax, data);
	return 0;
}
#else
static int anon_dax_drop(struct dev_dax *dev_dax, struct anon_dax_data *data)
{
	return -EBUSY;
}
#endif /* CONFIG_MEMORY_HOTREMOVE */

/*
 * mmap: turn the mapping into an ordinary ANONYMOUS mapping bound to the
 * private node, and let the core fault paths do the rest.
 *
 * Install the device's MPOL_F_PRIVATE bind as that policy, so every folio
 * (fault and swap-in) lands on the private node, exactly like an mbind().
 */
static int anon_dax_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct dev_dax *dev_dax = filp->private_data;
	struct anon_dax_data *data = dev_get_drvdata(&dev_dax->dev);
	int rc = 0, id;

	id = dax_read_lock();
	if (!dax_alive(dev_dax->dax_dev))
		rc = -ENXIO;
	dax_read_unlock(id);
	if (rc)
		return rc;

	/* Anondax mappings are not shared by definition, reject MAP_SHARED */
	if (vma->vm_flags & VM_SHARED)
		return -EINVAL;

	/* If policy creation failed, we cannot map the memory */
	if (!data->policy)
		return -ENXIO;

	/* Make the VM anonymous and attach the bind mempolicy */
	vma_set_anonymous(vma);
	mpol_get(data->policy);
	vma->vm_policy = data->policy;
	return 0;
}

static int anon_dax_open(struct inode *inode, struct file *filp)
{
	struct dax_device *dax_dev = inode_dax(inode);
	struct dev_dax *dev_dax = dax_get_private(dax_dev);

	filp->private_data = dev_dax;
	/*
	 * Deliberately NOT S_DAX: anondax mmap()s are ordinary anonymous
	 * mappings, so the vma must not look like dax (vma_is_dax()).
	 * That would wrongly exclude it from migration, NUMA balancing, etc.
	 */
	return 0;
}

static const struct file_operations anon_dax_fops = {
	.llseek = noop_llseek,
	.owner = THIS_MODULE,
	.open = anon_dax_open,
	.mmap = anon_dax_mmap,
};

static ssize_t hotplug_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct anon_dax_data *data = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%s\n", anon_dax_state_name[data->state]);
}

static ssize_t hotplug_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t len)
{
	struct dev_dax *dev_dax = to_dev_dax(dev);
	struct anon_dax_data *data = dev_get_drvdata(dev);
	int want, online_type;
	ssize_t rc;

	want = sysfs_match_string(anon_dax_state_name, buf);
	if (want < 0)
		return -EINVAL;

	rc = mutex_lock_interruptible(&data->lock);
	if (rc)
		return rc;

	if (want == data->state) {
		rc = len;
	} else if (want == ANON_DAX_UNPLUGGED) {
		rc = anon_dax_drop(dev_dax, data);
		if (!rc) {
			data->state = ANON_DAX_UNPLUGGED;
			rc = len;
		}
	} else if (data->state != ANON_DAX_UNPLUGGED) {
		/* unplug before changing the online zone */
		rc = -EBUSY;
	} else {
		online_type = (want == ANON_DAX_KERNEL) ?
			MMOP_ONLINE_KERNEL : MMOP_ONLINE_MOVABLE;
		rc = anon_dax_add(dev_dax, data, online_type);
		if (rc >= 0) {
			data->state = want;
			rc = len;
			/*
			 * The node is now private, so we can build a private
			 * mbind policy.  Build it once and hold it for the
			 * device's lifetime.  Best-effort: on failure, a normal
			 * fault still places folios correctly, but swap-in will
			 * likely misplace the folio.  Warn in this case.
			 */
			if (!data->policy) {
				struct mempolicy *pol;

				pol = mpol_private_bind(data->numa_node);
				if (IS_ERR(pol))
					dev_warn(dev, "private bind failed: %ld\n",
						 PTR_ERR(pol));
				else
					data->policy = pol;
			}
		}
	}

	mutex_unlock(&data->lock);
	return rc;
}
static DEVICE_ATTR_RW(hotplug);

/*
 * Define a NODE_PRIVATE_CAP_* opt-in toggle.  The bit is recorded in
 * data->caps while the device is unplugged and applied to the node at hotplug.
 * Dependencies between caps (e.g. demotion needs reclaim) are enforced by
 * node_private_register() at hotplug, so the setter only records the bit.
 */
#define ANON_DAX_CAP_ATTR(name, CAP)					\
static ssize_t name##_show(struct device *dev,				\
			   struct device_attribute *attr, char *buf)	\
{									\
	struct anon_dax_data *data = dev_get_drvdata(dev);		\
									\
	return sysfs_emit(buf, "%d\n", !!(data->caps & (CAP)));		\
}									\
static ssize_t name##_store(struct device *dev,				\
			    struct device_attribute *attr,		\
			    const char *buf, size_t len)		\
{									\
	struct anon_dax_data *data = dev_get_drvdata(dev);		\
	bool enable;							\
	ssize_t rc;							\
									\
	rc = kstrtobool(buf, &enable);					\
	if (rc)								\
		return rc;						\
									\
	rc = mutex_lock_interruptible(&data->lock);			\
	if (rc)								\
		return rc;						\
									\
	if (data->state != ANON_DAX_UNPLUGGED) {			\
		rc = -EBUSY;						\
	} else {							\
		if (enable)						\
			data->caps |= (CAP);				\
		else							\
			data->caps &= ~(CAP);				\
		rc = len;						\
	}								\
									\
	mutex_unlock(&data->lock);					\
	return rc;							\
}									\
static DEVICE_ATTR_RW(name)

ANON_DAX_CAP_ATTR(reclaim, NODE_PRIVATE_CAP_RECLAIM);

ANON_DAX_CAP_ATTR(mempolicy, NODE_PRIVATE_CAP_MEMPOLICY);

ANON_DAX_CAP_ATTR(hotunplug, NODE_PRIVATE_CAP_HOTUNPLUG);

static struct attribute *anon_dax_attrs[] = {
	&dev_attr_hotplug.attr,
	&dev_attr_reclaim.attr,
	&dev_attr_mempolicy.attr,
	&dev_attr_hotunplug.attr,
	NULL,
};
ATTRIBUTE_GROUPS(anon_dax);

static int dev_dax_anon_probe(struct dev_dax *dev_dax)
{
	struct dax_device *dax_dev = dev_dax->dax_dev;
	struct device *dev = &dev_dax->dev;
	unsigned long total_len = 0;
	struct anon_dax_data *data;
	struct cdev *cdev;
	struct inode *inode;
	int i, rc, numa_node;

	numa_node = dev_dax->target_node;
	if (numa_node < 0) {
		dev_warn(dev, "rejecting DAX region with invalid node: %d\n",
			 numa_node);
		return -EINVAL;
	}

	for (i = 0; i < dev_dax->nr_range; i++) {
		struct range range;

		if (anon_dax_range(dev_dax, i, &range))
			continue;
		total_len += range_len(&range);
	}
	if (!total_len) {
		dev_warn(dev, "no usable memory after alignment\n");
		return -EINVAL;
	}

	data = kzalloc_flex(*data, res, dev_dax->nr_range);
	if (!data)
		return -ENOMEM;
	mutex_init(&data->lock);
	data->state = ANON_DAX_UNPLUGGED;
	data->numa_node = numa_node;
	data->np.owner = data;

	rc = memory_group_register_static(numa_node, PFN_UP(total_len));
	if (rc < 0)
		goto err_group;
	data->mgid = rc;
	dev_set_drvdata(dev, data);

	/*
	 * Expose /dev/daxN.N immediately; the device starts UNPLUGGED and is
	 * onlined later via the "hotplug" attribute (faults SIGBUS until then).
	 */
	inode = dax_inode(dax_dev);
	cdev = inode->i_cdev;
	cdev_init(cdev, &anon_dax_fops);
	cdev->owner = dev->driver->owner;
	cdev_set_parent(cdev, &dev->kobj);
	rc = cdev_add(cdev, dev->devt, 1);
	if (rc)
		goto err_cdev;

	rc = device_add_groups(dev, anon_dax_groups);
	if (rc)
		goto err_groups;

	run_dax(dax_dev);
	return 0;

err_groups:
	cdev_del(cdev);
err_cdev:
	dev_set_drvdata(dev, NULL);
	memory_group_unregister(data->mgid);
err_group:
	kfree(data);
	return rc;
}

static void dev_dax_anon_remove(struct dev_dax *dev_dax)
{
	struct device *dev = &dev_dax->dev;
	struct anon_dax_data *data = dev_get_drvdata(dev);

	device_remove_groups(dev, anon_dax_groups);

	/* Stop new opens/faults, then tear down the char device. */
	kill_dev_dax(dev_dax);
	cdev_del(dev_dax->dax_dev ? dax_inode(dev_dax->dax_dev)->i_cdev : NULL);

	/* If memory is still mapped this fails and leaks (cannot migrate). */
	if (data->state != ANON_DAX_UNPLUGGED) {
		if (anon_dax_drop(dev_dax, data))
			return;
		data->state = ANON_DAX_UNPLUGGED;
	}

	/* Reached only after anon_dax_drop() confirmed nothing is mapped. */
	mpol_put(data->policy);

	memory_group_unregister(data->mgid);
	dev_set_drvdata(dev, NULL);
	kfree(data);
}

static struct dax_device_driver device_dax_anon_driver = {
	.probe = dev_dax_anon_probe,
	.remove = dev_dax_anon_remove,
	.type = DAXDRV_ANON_TYPE,
};

static int __init dax_anon_init(void)
{
	int rc;

	anon_dax_name = kstrdup_const("System RAM (anondax)", GFP_KERNEL);
	if (!anon_dax_name)
		return -ENOMEM;

	rc = dax_driver_register(&device_dax_anon_driver);
	if (rc)
		kfree_const(anon_dax_name);
	return rc;
}

static void __exit dax_anon_exit(void)
{
	dax_driver_unregister(&device_dax_anon_driver);
	kfree_const(anon_dax_name);
}

MODULE_AUTHOR("Gregory Price");
MODULE_DESCRIPTION("Anonymous DAX: mm managed DAX memory on a private node");
MODULE_LICENSE("GPL");
module_init(dax_anon_init);
module_exit(dax_anon_exit);
MODULE_ALIAS_DAX_DEVICE(0);
