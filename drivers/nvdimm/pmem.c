/*
 * Persistent Memory Driver
 *
 * Copyright (c) 2014-2015, Intel Corporation.
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
#include "pmem.h"

static blk_qc_t pmem_make_request(struct request_queue *q, struct bio *bio)
{
	blk_status_t rc = 0;
	bool do_acct;
	unsigned long start;
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct pmem_device *pmem = q->queuedata;
	struct nd_region *nd_region = to_region(pmem);

	if (bio->bi_opf & REQ_PREFLUSH)
		nvdimm_flush(nd_region);

	do_acct = nd_iostat_start(bio, &start);
	bio_for_each_segment(bvec, bio, iter) {
		rc = pmem_do_bvec(pmem, bvec.bv_page, bvec.bv_len,
				bvec.bv_offset, op_is_write(bio_op(bio)),
				iter.bi_sector);
		if (rc) {
			bio->bi_status = rc;
			break;
		}
	}
	if (do_acct)
		nd_iostat_end(bio, start);

	if (bio->bi_opf & REQ_FUA)
		nvdimm_flush(nd_region);

	bio_endio(bio);
	return BLK_QC_T_NONE;
}

static const struct block_device_operations pmem_fops = {
	.owner =		THIS_MODULE,
	.rw_page =		pmem_rw_page,
	.revalidate_disk =	nvdimm_revalidate_disk,
};

static const struct dax_operations pmem_dax_ops = {
	.direct_access = pmem_dax_direct_access,
	.copy_from_iter = pmem_copy_from_iter,
	.flush = pmem_dax_flush,
};

static const struct attribute_group *pmem_attribute_groups[] = {
	&dax_attribute_group,
	NULL,
};

static void pmem_release_queue(void *q)
{
	blk_cleanup_queue(q);
}

static int pmem_attach_disk(struct device *dev,
		struct nd_namespace_common *ndns)
{
	struct pmem_device *pmem;
	struct request_queue *q;
	struct resource pfn_res;
	struct vmem_altmap *altmap = NULL;
	int rc;

	pmem = pmem_core_setup_pmem(dev, ndns, &pfn_res, altmap);
	if (!pmem)
		return -ENXIO;

	q = blk_alloc_queue_node(GFP_KERNEL, dev_to_node(dev));
	if (!q)
		return -ENOMEM;

	pmem->q = q;
	pmem_core_setup_queue(dev, pmem, ndns);
	blk_queue_make_request(q, pmem_make_request);
	blk_queue_max_hw_sectors(q, UINT_MAX);

	if (devm_add_action_or_reset(dev, pmem_release_queue, q))
		return -ENOMEM;

	rc = pmem_core_remap_pages(dev, pmem, ndns, &pfn_res, altmap);
	if (rc < 0)
		return rc;

	rc = pmem_core_setup_disk(dev, pmem, ndns, &pmem_fops,
			&pmem_dax_ops, pmem_attribute_groups);
	if (rc < 0)
		return rc;

	return 0;
}

static int nd_pmem_probe(struct device *dev)
{
	struct nd_namespace_common *ndns;

	ndns = nvdimm_namespace_common_probe(dev);
	if (IS_ERR(ndns))
		return PTR_ERR(ndns);

	if (devm_nsio_enable(dev, to_nd_namespace_io(&ndns->dev)))
		return -ENXIO;

	if (is_nd_btt(dev))
		return nvdimm_namespace_attach_btt(ndns);

	if (is_nd_pfn(dev))
		return pmem_attach_disk(dev, ndns);

	/* if we find a valid info-block we'll come back as that personality */
	if (nd_btt_probe(dev, ndns) == 0 || nd_pfn_probe(dev, ndns) == 0
			|| nd_dax_probe(dev, ndns) == 0)
		return -ENXIO;

	/* ...otherwise we're just a raw pmem device */
	return pmem_attach_disk(dev, ndns);
}

MODULE_ALIAS("pmem");
MODULE_ALIAS_ND_DEVICE(ND_DEVICE_NAMESPACE_IO);
MODULE_ALIAS_ND_DEVICE(ND_DEVICE_NAMESPACE_PMEM);
static struct nd_device_driver nd_pmem_driver = {
	.probe = nd_pmem_probe,
	.remove = nd_pmem_remove,
	.notify = nd_pmem_notify,
	.shutdown = nd_pmem_shutdown,
	.drv = {
		.name = "nd_pmem",
	},
	.type = ND_DRIVER_NAMESPACE_IO | ND_DRIVER_NAMESPACE_PMEM,
};

static int __init pmem_init(void)
{
	return nd_driver_register(&nd_pmem_driver);
}
module_init(pmem_init);

static void pmem_exit(void)
{
	driver_unregister(&nd_pmem_driver.drv);
}
module_exit(pmem_exit);

MODULE_AUTHOR("Ross Zwisler <ross.zwisler@linux.intel.com>");
MODULE_LICENSE("GPL v2");
