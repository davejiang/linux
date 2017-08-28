/*
 * Persistent Memory Block Driver shared code
 * Copyright (c) 2014-2017, Intel Corporation.
 * Copyright (c) 2015, Christoph Hellwig <hch@lst.de>.
 * Copyright (c) 2015, Boaz Harrosh <boaz@plexistor.com>.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/badblocks.h>
#include <linux/memremap.h>
#include <linux/pfn_t.h>
#include <linux/uio.h>
#include "pmem.h"
#include "pfn.h"

blk_status_t pmem_clear_poison(struct pmem_device *pmem,
		phys_addr_t offset, unsigned int len)
{
	struct device *dev = to_dev(pmem);
	sector_t sector;
	long cleared;
	blk_status_t rc = BLK_STS_OK;

	sector = (offset - pmem->data_offset) / 512;

	cleared = nvdimm_clear_poison(dev, pmem->phys_addr + offset, len);
	if (cleared < len)
		rc = BLK_STS_IOERR;
	if (cleared > 0 && cleared / 512) {
		cleared /= 512;
		dev_dbg(dev, "%s: %#llx clear %ld sector%s\n", __func__,
				(unsigned long long) sector, cleared,
				cleared > 1 ? "s" : "");
		badblocks_clear(&pmem->bb, sector, cleared);
		if (pmem->bb_state)
			sysfs_notify_dirent(pmem->bb_state);
	}

	arch_invalidate_pmem(pmem->virt_addr + offset, len);

	return rc;
}
EXPORT_SYMBOL_GPL(pmem_clear_poison);

void write_pmem(void *pmem_addr, struct page *page,
		unsigned int off, unsigned int len)
{
	void *mem = kmap_atomic(page);

	memcpy_flushcache(pmem_addr, mem + off, len);
	kunmap_atomic(mem);
}
EXPORT_SYMBOL_GPL(write_pmem);

blk_status_t read_pmem(struct page *page, unsigned int off,
		void *pmem_addr, unsigned int len)
{
	int rc;
	void *mem = kmap_atomic(page);

	rc = memcpy_mcsafe(mem + off, pmem_addr, len);
	kunmap_atomic(mem);
	if (rc)
		return BLK_STS_IOERR;
	return BLK_STS_OK;
}
EXPORT_SYMBOL_GPL(read_pmem);

blk_status_t pmem_do_bvec(struct pmem_device *pmem, struct page *page,
			unsigned int len, unsigned int off, bool is_write,
			sector_t sector)
{
	blk_status_t rc = BLK_STS_OK;
	bool bad_pmem = false;
	phys_addr_t pmem_off = sector * 512 + pmem->data_offset;
	void *pmem_addr = pmem->virt_addr + pmem_off;

	if (unlikely(is_bad_pmem(&pmem->bb, sector, len)))
		bad_pmem = true;

	if (!is_write) {
		if (unlikely(bad_pmem))
			rc = BLK_STS_IOERR;
		else {
			rc = read_pmem(page, off, pmem_addr, len);
			flush_dcache_page(page);
		}
	} else {
		/*
		 * Note that we write the data both before and after
		 * clearing poison.  The write before clear poison
		 * handles situations where the latest written data is
		 * preserved and the clear poison operation simply marks
		 * the address range as valid without changing the data.
		 * In this case application software can assume that an
		 * interrupted write will either return the new good
		 * data or an error.
		 *
		 * However, if pmem_clear_poison() leaves the data in an
		 * indeterminate state we need to perform the write
		 * after clear poison.
		 */
		flush_dcache_page(page);
		write_pmem(pmem_addr, page, off, len);
		if (unlikely(bad_pmem)) {
			rc = pmem_clear_poison(pmem, pmem_off, len);
			write_pmem(pmem_addr, page, off, len);
		}
	}

	return rc;
}
EXPORT_SYMBOL_GPL(pmem_do_bvec);

int pmem_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, bool is_write)
{
	struct pmem_device *pmem = bdev->bd_queue->queuedata;
	blk_status_t rc;

	rc = pmem_do_bvec(pmem, page, PAGE_SIZE, 0, is_write, sector);

	/*
	 * The ->rw_page interface is subtle and tricky.  The core
	 * retries on any error, so we can only invoke page_endio() in
	 * the successful completion case.  Otherwise, we'll see crashes
	 * caused by double completion.
	 */
	if (rc == 0)
		page_endio(page, is_write, 0);

	return blk_status_to_errno(rc);
}
EXPORT_SYMBOL_GPL(pmem_rw_page);

/* see "strong" declaration in tools/testing/nvdimm/pmem-dax.c */
__weak long __pmem_direct_access(struct pmem_device *pmem, pgoff_t pgoff,
		long nr_pages, void **kaddr, pfn_t *pfn)
{
	resource_size_t offset = PFN_PHYS(pgoff) + pmem->data_offset;

	if (unlikely(is_bad_pmem(&pmem->bb, PFN_PHYS(pgoff) / 512,
					PFN_PHYS(nr_pages))))
		return -EIO;
	*kaddr = pmem->virt_addr + offset;
	*pfn = phys_to_pfn_t(pmem->phys_addr + offset, pmem->pfn_flags);

	/*
	 * If badblocks are present, limit known good range to the
	 * requested range.
	 */
	if (unlikely(pmem->bb.count))
		return nr_pages;
	return PHYS_PFN(pmem->size - pmem->pfn_pad - offset);
}

long pmem_dax_direct_access(struct dax_device *dax_dev,
		pgoff_t pgoff, long nr_pages, void **kaddr, pfn_t *pfn)
{
	struct pmem_device *pmem = dax_get_private(dax_dev);

	return __pmem_direct_access(pmem, pgoff, nr_pages, kaddr, pfn);
}
EXPORT_SYMBOL_GPL(pmem_dax_direct_access);

size_t pmem_copy_from_iter(struct dax_device *dax_dev, pgoff_t pgoff,
		void *addr, size_t bytes, struct iov_iter *i)
{
	return copy_from_iter_flushcache(addr, bytes, i);
}
EXPORT_SYMBOL_GPL(pmem_copy_from_iter);

void pmem_dax_flush(struct dax_device *dax_dev, pgoff_t pgoff,
		void *addr, size_t size)
{
	arch_wb_cache_pmem(addr, size);
}
EXPORT_SYMBOL_GPL(pmem_dax_flush);

void nd_pmem_notify(struct device *dev, enum nvdimm_event event)
{
	struct nd_region *nd_region;
	resource_size_t offset = 0, end_trunc = 0;
	struct nd_namespace_common *ndns;
	struct nd_namespace_io *nsio;
	struct resource res;
	struct badblocks *bb;
	struct kernfs_node *bb_state;

	if (event != NVDIMM_REVALIDATE_POISON)
		return;

	if (is_nd_btt(dev)) {
		struct nd_btt *nd_btt = to_nd_btt(dev);

		ndns = nd_btt->ndns;
		nd_region = to_nd_region(ndns->dev.parent);
		nsio = to_nd_namespace_io(&ndns->dev);
		bb = &nsio->bb;
		bb_state = NULL;
	} else {
		struct pmem_device *pmem = dev_get_drvdata(dev);

		nd_region = to_region(pmem);
		bb = &pmem->bb;
		bb_state = pmem->bb_state;

		if (is_nd_pfn(dev)) {
			struct nd_pfn *nd_pfn = to_nd_pfn(dev);
			struct nd_pfn_sb *pfn_sb = nd_pfn->pfn_sb;

			ndns = nd_pfn->ndns;
			offset = pmem->data_offset +
					__le32_to_cpu(pfn_sb->start_pad);
			end_trunc = __le32_to_cpu(pfn_sb->end_trunc);
		} else {
			ndns = to_ndns(dev);
		}

		nsio = to_nd_namespace_io(&ndns->dev);
	}

	res.start = nsio->res.start + offset;
	res.end = nsio->res.end - end_trunc;
	nvdimm_badblocks_populate(nd_region, bb, &res);
	if (bb_state)
		sysfs_notify_dirent(bb_state);
}
EXPORT_SYMBOL_GPL(nd_pmem_notify);

static void pmem_freeze_queue(void *q)
{
	blk_freeze_queue_start(q);
}

int pmem_core_remap_pages(struct device *dev, struct pmem_device *pmem,
		struct nd_namespace_common *ndns, struct resource *pfn_res,
		struct vmem_altmap *altmap)
{
	struct nd_namespace_io *nsio = to_nd_namespace_io(&ndns->dev);
	void *addr;
	struct resource *res = &nsio->res;

	pmem->pfn_flags = PFN_DEV;
	if (is_nd_pfn(dev)) {
		struct nd_pfn *nd_pfn = to_nd_pfn(dev);
		struct nd_pfn_sb *pfn_sb;

		addr = devm_memremap_pages(dev, pfn_res,
				&pmem->q->q_usage_counter, altmap);
		pfn_sb = nd_pfn->pfn_sb;
		pmem->data_offset = le64_to_cpu(pfn_sb->dataoff);
		pmem->pfn_pad = resource_size(res) - resource_size(pfn_res);
		pmem->pfn_flags |= PFN_MAP;
		res = pfn_res; /* for badblocks populate */
		res->start += pmem->data_offset;
	} else if (pmem_should_map_pages(dev)) {
		addr = devm_memremap_pages(dev, &nsio->res,
				&pmem->q->q_usage_counter, NULL);
		pmem->pfn_flags |= PFN_MAP;
	} else
		addr = devm_memremap(dev, pmem->phys_addr,
				pmem->size, ARCH_MEMREMAP_PMEM);

	/*
	 * At release time the queue must be frozen before
	 * devm_memremap_pages is unwound
	 */
	if (devm_add_action_or_reset(dev, pmem_freeze_queue, pmem->q))
		return -ENXIO;

	if (IS_ERR(addr))
		return -ENXIO;

	pmem->virt_addr = addr;
	return 0;
}
EXPORT_SYMBOL_GPL(pmem_core_remap_pages);

static void pmem_release_disk(void *__pmem)
{
	struct pmem_device *pmem = __pmem;

	kill_dax(pmem->dax_dev);
	put_dax(pmem->dax_dev);
	del_gendisk(pmem->disk);
	put_disk(pmem->disk);
}

int pmem_core_setup_disk(struct device *dev,
		struct pmem_device *pmem,
		struct nd_namespace_common *ndns,
		const struct block_device_operations *block_ops,
		const struct dax_operations *dax_ops,
		const struct attribute_group **attribs)
{
	struct device *gendev;
	struct gendisk *disk;
	struct dax_device *dax_dev;
	struct nd_region *nd_region = to_nd_region(dev->parent);
	int wbc, fua;
	int nid = dev_to_node(dev);
	struct nd_namespace_io *nsio = to_nd_namespace_io(&ndns->dev);
	struct resource *res = &nsio->res;

	wbc = nvdimm_has_cache(nd_region);
	fua = nvdimm_has_flush(nd_region);
	if (!IS_ENABLED(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) || fua < 0) {
		dev_warn(dev, "unable to guarantee persistence of writes\n");
		fua = 0;
	}

	disk = alloc_disk_node(0, nid);
	if (!disk)
		return -ENOMEM;
	pmem->disk = disk;

	disk->fops = block_ops;
	disk->queue = pmem->q;
	disk->flags = GENHD_FL_EXT_DEVT;
	nvdimm_namespace_disk_name(ndns, disk->disk_name);
	set_capacity(disk, (pmem->size - pmem->pfn_pad - pmem->data_offset)
			/ 512);

	if (devm_init_badblocks(dev, &pmem->bb))
		return -ENXIO;

	nvdimm_badblocks_populate(nd_region, &pmem->bb, res);
	disk->bb = &pmem->bb;

	dax_dev = alloc_dax(pmem, disk->disk_name, dax_ops);
	if (!dax_dev) {
		put_disk(disk);
		return -ENOMEM;
	}

	dax_write_cache(dax_dev, wbc);
	pmem->dax_dev = dax_dev;
	gendev = disk_to_dev(disk);
	gendev->groups = attribs;

	device_add_disk(dev, disk);
	if (devm_add_action_or_reset(dev, pmem_release_disk, pmem))
		return -ENOMEM;

	revalidate_disk(disk);

	pmem->bb_state = sysfs_get_dirent(disk_to_dev(disk)->kobj.sd,
					  "badblocks");
	if (!pmem->bb_state)
		dev_warn(dev, "'badblocks' notification disabled\n");

	return 0;
}
EXPORT_SYMBOL_GPL(pmem_core_setup_disk);

void pmem_core_setup_queue(struct device *dev, struct pmem_device *pmem,
		struct nd_namespace_common *ndns)
{
	struct nd_region *nd_region = to_nd_region(dev->parent);
	int fua, wbc;

	wbc = nvdimm_has_cache(nd_region);
	fua = nvdimm_has_flush(nd_region);
	if (!IS_ENABLED(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) || fua < 0) {
		dev_warn(dev, "unable to guarantee persistence of writes\n");
		fua = 0;
	}

	blk_queue_write_cache(pmem->q, wbc, fua);
	blk_queue_physical_block_size(pmem->q, PAGE_SIZE);
	blk_queue_logical_block_size(pmem->q, pmem_sector_size(ndns));
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, pmem->q);
	queue_flag_set_unlocked(QUEUE_FLAG_DAX, pmem->q);
	pmem->q->queuedata = pmem;
}
EXPORT_SYMBOL_GPL(pmem_core_setup_queue);

struct pmem_device *pmem_core_setup_pmem(struct device *dev,
		struct nd_namespace_common *ndns, struct resource *pfn_res,
		struct vmem_altmap *altmap)
{
	struct nd_namespace_io *nsio = to_nd_namespace_io(&ndns->dev);
	struct resource *res = &nsio->res;
	struct pmem_device *pmem;
	struct nd_pfn *nd_pfn = NULL;
	struct vmem_altmap __altmap;

	/* while nsio_rw_bytes is active, parse a pfn info block if present */
	if (is_nd_pfn(dev)) {
		nd_pfn = to_nd_pfn(dev);
		altmap = nvdimm_setup_pfn(nd_pfn, pfn_res, &__altmap);
		if (IS_ERR(altmap))
			return NULL;
	}

	/* we're attaching a block device, disable raw namespace access */
	devm_nsio_disable(dev, nsio);

	pmem = devm_kzalloc(dev, sizeof(*pmem), GFP_KERNEL);
	if (!pmem)
		return NULL;

	dev_set_drvdata(dev, pmem);
	pmem->phys_addr = res->start;
	pmem->size = resource_size(res);
	if (!devm_request_mem_region(dev, res->start, resource_size(res),
				dev_name(&ndns->dev))) {
		dev_warn(dev, "could not reserve region %pR\n", res);
		return NULL;
	}


	return pmem;
}
EXPORT_SYMBOL_GPL(pmem_core_setup_pmem);

int nd_pmem_remove(struct device *dev)
{
	struct pmem_device *pmem = dev_get_drvdata(dev);

	if (is_nd_btt(dev))
		nvdimm_namespace_detach_btt(to_nd_btt(dev));
	else {
		/*
		 * Note, this assumes device_lock() context to not race
		 * nd_pmem_notify()
		 */
		sysfs_put(pmem->bb_state);
		pmem->bb_state = NULL;
	}
	nvdimm_flush(to_nd_region(dev->parent));

	return 0;
}
EXPORT_SYMBOL_GPL(nd_pmem_remove);

void nd_pmem_shutdown(struct device *dev)
{
	nvdimm_flush(to_nd_region(dev->parent));
}
EXPORT_SYMBOL_GPL(nd_pmem_shutdown);

MODULE_LICENSE("GPL v2");
