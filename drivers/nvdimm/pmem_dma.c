/*
 * Persistent Memory Block DMA Driver
 * Copyright (c) 2017, Intel Corporation.
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
#include <linux/blk-mq.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/nodemask.h>
#include "pmem.h"
#include "pfn.h"
#include "nd.h"

/* After doing some measurements with various queue depth while running
 * fio at 4k with 16 processes, it seems that a queue depth of 128
 * provides the best performance. We can adjust this later when new
 * data says otherwise.
 */
static int queue_depth = 128;

struct pmem_cmd {
	struct request *rq;
	struct dma_chan *chan;
	int sg_nents;
	struct scatterlist sg[];
};

static void pmem_release_queue(void *data)
{
	struct pmem_device *pmem = data;

	blk_cleanup_queue(pmem->q);
	blk_mq_free_tag_set(&pmem->tag_set);
}

static void nd_pmem_dma_callback(void *data,
		const struct dmaengine_result *res)
{
	struct pmem_cmd *cmd = data;
	struct request *req = cmd->rq;
	struct request_queue *q = req->q;
	struct pmem_device *pmem = q->queuedata;
	struct nd_region *nd_region = to_region(pmem);
	struct device *dev = to_dev(pmem);
	blk_status_t blk_status = BLK_STS_OK;

	if (res) {
		switch (res->result) {
		case DMA_TRANS_READ_FAILED:
		case DMA_TRANS_WRITE_FAILED:
		case DMA_TRANS_ABORTED:
			dev_dbg(dev, "bio failed\n");
			blk_status = BLK_STS_IOERR;
			break;
		case DMA_TRANS_NOERROR:
		default:
			break;
		}
	}

	if (req_op(req) == REQ_OP_WRITE && req->cmd_flags & REQ_FUA)
		nvdimm_flush(nd_region);

	blk_mq_end_request(cmd->rq, blk_status);
}

static int pmem_check_bad_pmem(struct pmem_cmd *cmd, bool is_write)
{
	struct request *req = cmd->rq;
	struct request_queue *q = req->q;
	struct pmem_device *pmem = q->queuedata;
	struct bio_vec bvec;
	struct req_iterator iter;

	rq_for_each_segment(bvec, req, iter) {
		sector_t sector = iter.iter.bi_sector;
		unsigned int len = bvec.bv_len;
		unsigned int off = bvec.bv_offset;

		if (unlikely(is_bad_pmem(&pmem->bb, sector, len))) {
			if (is_write) {
				struct page *page = bvec.bv_page;
				phys_addr_t pmem_off = sector * 512 +
					pmem->data_offset;
				void *pmem_addr = pmem->virt_addr + pmem_off;

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
				pmem_clear_poison(pmem, pmem_off, len);
				write_pmem(pmem_addr, page, off, len);
			} else
				return -EIO;
		}
	}

	return 0;
}

static blk_status_t pmem_handle_cmd_dma(struct pmem_cmd *cmd, bool is_write)
{
	struct request *req = cmd->rq;
	struct request_queue *q = req->q;
	struct pmem_device *pmem = q->queuedata;
	struct device *dev = to_dev(pmem);
	phys_addr_t pmem_off = blk_rq_pos(req) * 512 + pmem->data_offset;
	void *pmem_addr = pmem->virt_addr + pmem_off;
	size_t len;
	struct dma_device *dma = cmd->chan->device;
	struct dmaengine_unmap_data *unmap;
	dma_cookie_t cookie;
	struct dma_async_tx_descriptor *txd;
	struct page *page;
	unsigned int off;
	int rc;
	blk_status_t blk_status = BLK_STS_OK;
	enum dma_data_direction dir;
	dma_addr_t dma_addr;

	rc = pmem_check_bad_pmem(cmd, is_write);
	if (rc < 0) {
		blk_status = BLK_STS_IOERR;
		goto err;
	}

	unmap = dmaengine_get_unmap_data(dma->dev, 2, GFP_NOWAIT);
	if (!unmap) {
		dev_dbg(dev, "failed to get dma unmap data\n");
		blk_status = BLK_STS_IOERR;
		goto err;
	}

	/*
	 * If reading from pmem, writing to scatterlist,
	 * and if writing to pmem, reading from scatterlist.
	 */
	dir = is_write ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
	cmd->sg_nents = blk_rq_map_sg(req->q, req, cmd->sg);
	if (cmd->sg_nents < 1) {
		blk_status = BLK_STS_IOERR;
		goto err;
	}

	WARN_ON_ONCE(cmd->sg_nents > pmem->sg_allocated);

	rc = dma_map_sg(dma->dev, cmd->sg, cmd->sg_nents, dir);
	if (rc < 1) {
		dev_dbg(dma->dev, "DMA scatterlist mapping error\n");
		blk_status = BLK_STS_IOERR;
		goto err;
	}

	unmap->unmap_sg.sg = cmd->sg;
	unmap->sg_nents = cmd->sg_nents;
	if (is_write)
		unmap->from_sg = 1;
	else
		unmap->to_sg = 1;

	len = blk_rq_payload_bytes(req);
	page = virt_to_page(pmem_addr);
	off = offset_in_page(pmem_addr);
	dir = is_write ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	dma_addr = dma_map_page(dma->dev, page, off, len, dir);
	if (dma_mapping_error(dma->dev, unmap->addr[0])) {
		dev_dbg(dma->dev, "DMA buffer mapping error\n");
		blk_status = BLK_STS_IOERR;
		goto err_unmap;
	}

	unmap->unmap_sg.buf_phys = dma_addr;
	unmap->len = len;
	if (is_write)
		unmap->to_cnt = 1;
	else
		unmap->from_cnt = 1;

	txd = dmaengine_prep_dma_memcpy_sg(cmd->chan,
				cmd->sg, cmd->sg_nents, dma_addr,
				!is_write, DMA_PREP_INTERRUPT);
	if (!txd) {
		dev_dbg(dma->dev, "dma prep failed\n");
		blk_status = BLK_STS_IOERR;
		goto err_unmap;
	}

	txd->callback_result = nd_pmem_dma_callback;
	txd->callback_param = cmd;
	dma_set_unmap(txd, unmap);
	dmaengine_unmap_put(unmap);
	cookie = dmaengine_submit(txd);
	if (dma_submit_error(cookie)) {
		dev_dbg(dma->dev, "dma submit error\n");
		blk_status = BLK_STS_IOERR;
		goto err_set_unmap;
	}

	dma_async_issue_pending(cmd->chan);
	return BLK_STS_OK;

err_set_unmap:
	dmaengine_unmap_put(unmap);
err_unmap:
	dmaengine_unmap_put(unmap);
err:
	blk_mq_end_request(cmd->rq, blk_status);
	return blk_status;
}

static blk_status_t pmem_handle_cmd(struct pmem_cmd *cmd, bool is_write)
{
	struct request *req = cmd->rq;
	struct request_queue *q = req->q;
	struct pmem_device *pmem = q->queuedata;
	struct nd_region *nd_region = to_region(pmem);
	struct bio_vec bvec;
	struct req_iterator iter;
	blk_status_t blk_status = BLK_STS_OK;

	rq_for_each_segment(bvec, req, iter) {
		blk_status = pmem_do_bvec(pmem, bvec.bv_page, bvec.bv_len,
				bvec.bv_offset, is_write,
				iter.iter.bi_sector);
		if (blk_status != BLK_STS_OK)
			break;
	}

	if (is_write && req->cmd_flags & REQ_FUA)
		nvdimm_flush(nd_region);

	blk_mq_end_request(cmd->rq, blk_status);

	return blk_status;
}

typedef blk_status_t (*pmem_do_io)(struct pmem_cmd *cmd, bool is_write);

static blk_status_t pmem_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct pmem_cmd *cmd = blk_mq_rq_to_pdu(bd->rq);
	struct request *req = cmd->rq = bd->rq;
	struct request_queue *q = req->q;
	struct pmem_device *pmem = q->queuedata;
	struct nd_region *nd_region = to_region(pmem);
	struct device *dev = to_dev(pmem);
	blk_status_t blk_status = BLK_STS_OK;
	pmem_do_io do_io;

	blk_mq_start_request(req);
	if (pmem->has_dma)
		cmd->chan = dma_find_channel(DMA_MEMCPY_SG);
	else
		cmd->chan = NULL;

	if (cmd->chan)
		do_io = pmem_handle_cmd_dma;
	else
		do_io = pmem_handle_cmd;

	switch (req_op(req)) {
	case REQ_OP_FLUSH:
		nvdimm_flush(nd_region);
		blk_mq_end_request(cmd->rq, BLK_STS_OK);
		break;
	case REQ_OP_READ:
		blk_status = do_io(cmd, false);
		break;
	case REQ_OP_WRITE:
		blk_status = do_io(cmd, true);
		break;
	default:
		dev_warn(dev, "op %#x not supported\n", req_op(req));
		blk_status = BLK_STS_NOTSUPP;
		break;
	}

	if (blk_status != BLK_STS_OK)
		blk_mq_end_request(cmd->rq, blk_status);

	return blk_status;
}

static const struct blk_mq_ops pmem_mq_ops = {
	.queue_rq	= pmem_queue_rq,
};

static const struct attribute_group *pmem_attribute_groups[] = {
	&dax_attribute_group,
	NULL,
};

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

static bool pmem_dma_filter_fn(struct dma_chan *chan, void *node)
{
	return dev_to_node(&chan->dev->device) == (int)(unsigned long)node;
}

static int pmem_attach_disk(struct device *dev,
		struct nd_namespace_common *ndns)
{
	struct pmem_device *pmem;
	int rc;
	struct resource pfn_res;
	struct vmem_altmap *altmap = NULL;
	struct dma_chan *chan = NULL;

	pmem = pmem_core_setup_pmem(dev, ndns, &pfn_res, altmap);
	if (!pmem)
		return -ENXIO;

	chan = dma_find_channel(DMA_MEMCPY_SG);
	if (!chan) {
		pmem->has_dma = 0;
		dev_warn(dev, "Forced back to CPU, no DMA\n");
	} else
		pmem->has_dma = 1;

	/* If we are not in memory mode, we can't DMA */
	if (!is_nd_pfn(dev))
		pmem->has_dma = 0;

	pmem->tag_set.ops = &pmem_mq_ops;
	if (pmem->has_dma) {
		dma_cap_mask_t dma_mask;
		int node = 0, count;

		dma_cap_zero(dma_mask);
		dma_cap_set(DMA_MEMCPY_SG, dma_mask);
		count = dma_get_channel_count(&dma_mask, pmem_dma_filter_fn,
				(void *)(unsigned long)node);
		if (count)
			pmem->tag_set.nr_hw_queues = count;
		else {
			pmem->has_dma = 0;
			pmem->tag_set.nr_hw_queues = num_online_cpus();
		}
	} else
		pmem->tag_set.nr_hw_queues = num_online_cpus();

	dev_dbg(dev, "%d HW queues allocated\n", pmem->tag_set.nr_hw_queues);

	pmem->tag_set.queue_depth = queue_depth;
	pmem->tag_set.numa_node = dev_to_node(dev);

	if (pmem->has_dma) {
		pmem->sg_allocated = (SZ_4K - sizeof(struct pmem_cmd)) /
			sizeof(struct scatterlist);
		pmem->tag_set.cmd_size = sizeof(struct pmem_cmd) +
			sizeof(struct scatterlist) * pmem->sg_allocated;
	} else
		pmem->tag_set.cmd_size = sizeof(struct pmem_cmd);

	pmem->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	pmem->tag_set.driver_data = pmem;

	rc = blk_mq_alloc_tag_set(&pmem->tag_set);
	if (rc < 0)
		return rc;

	pmem->q = blk_mq_init_queue(&pmem->tag_set);
	if (IS_ERR(pmem->q)) {
		blk_mq_free_tag_set(&pmem->tag_set);
		return -ENOMEM;
	}

	pmem_core_setup_queue(dev, pmem, ndns);

	if (pmem->has_dma) {
		u64 xfercap = dma_get_desc_xfercap(chan);

		/* set it to some sane size if DMA driver didn't export */
		if (xfercap == 0)
			xfercap = SZ_1M;

		dev_dbg(dev, "xfercap: %#llx\n", xfercap);
		/* max xfer size is per_descriptor_cap * num_of_sg */
		blk_queue_max_hw_sectors(pmem->q,
				pmem->sg_allocated * xfercap / 512);
		blk_queue_max_segments(pmem->q, pmem->sg_allocated);
	}
		blk_queue_max_hw_sectors(pmem->q, UINT_MAX);

	if (devm_add_action_or_reset(dev, pmem_release_queue, pmem)) {
		pmem_release_queue(pmem);
		return -ENOMEM;
	}

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

static struct nd_device_driver nd_pmem_driver = {
	.probe = nd_pmem_probe,
	.remove = nd_pmem_remove,
	.notify = nd_pmem_notify,
	.shutdown = nd_pmem_shutdown,
	.drv = {
		.name = "nd_pmem_dma",
	},
	.type = ND_DRIVER_NAMESPACE_IO | ND_DRIVER_NAMESPACE_PMEM,
};

static int __init pmem_init(void)
{
	dmaengine_get();
	return nd_driver_register(&nd_pmem_driver);
}
module_init(pmem_init);

static void pmem_exit(void)
{
	dmaengine_put();
	driver_unregister(&nd_pmem_driver.drv);
}
module_exit(pmem_exit);

MODULE_SOFTDEP("pre: dmaengine");
MODULE_LICENSE("GPL v2");
