#ifndef __NVDIMM_PMEM_H__
#define __NVDIMM_PMEM_H__
#include <linux/badblocks.h>
#include <linux/types.h>
#include <linux/pfn_t.h>
#include <linux/fs.h>
#include <linux/blk-mq.h>
#include <linux/dax.h>
#include "nd.h"

#ifdef CONFIG_ARCH_HAS_PMEM_API
#define ARCH_MEMREMAP_PMEM MEMREMAP_WB
void arch_wb_cache_pmem(void *addr, size_t size);
void arch_invalidate_pmem(void *addr, size_t size);
#else
#define ARCH_MEMREMAP_PMEM MEMREMAP_WT
static inline void arch_wb_cache_pmem(void *addr, size_t size)
{
}
static inline void arch_invalidate_pmem(void *addr, size_t size)
{
}
#endif

/* this definition is in it's own header for tools/testing/nvdimm to consume */
struct pmem_device {
	/* One contiguous memory region per device */
	phys_addr_t		phys_addr;
	/* when non-zero this device is hosting a 'pfn' instance */
	phys_addr_t		data_offset;
	u64			pfn_flags;
	void			*virt_addr;
	/* immutable base size of the namespace */
	size_t			size;
	/* trim size when namespace capacity has been section aligned */
	u32			pfn_pad;
	struct kernfs_node	*bb_state;
	struct badblocks	bb;
	struct dax_device	*dax_dev;
	struct gendisk		*disk;
	struct blk_mq_tag_set	tag_set;
	struct request_queue	*q;
	unsigned int		sg_allocated;
	bool			has_dma;
};

static inline struct device *to_dev(struct pmem_device *pmem)
{
	/*
	 * nvdimm bus services need a 'dev' parameter, and we record the device
	 * at init in bb.dev.
	 */
	return pmem->bb.dev;
}

static inline struct nd_region *to_region(struct pmem_device *pmem)
{
	return to_nd_region(to_dev(pmem)->parent);
}

struct device *to_dev(struct pmem_device *pmem);
struct nd_region *to_region(struct pmem_device *pmem);
blk_status_t pmem_clear_poison(struct pmem_device *pmem,
		phys_addr_t offset, unsigned int len);
void write_pmem(void *pmem_addr, struct page *page,
		unsigned int off, unsigned int len);
blk_status_t read_pmem(struct page *page, unsigned int off,
		void *pmem_addr, unsigned int len);
blk_status_t pmem_do_bvec(struct pmem_device *pmem, struct page *page,
			unsigned int len, unsigned int off, bool is_write,
			sector_t sector);
int pmem_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, bool is_write);
void nd_pmem_notify(struct device *dev, enum nvdimm_event event);
long pmem_dax_direct_access(struct dax_device *dax_dev,
		pgoff_t pgoff, long nr_pages, void **kaddr, pfn_t *pfn);
size_t pmem_copy_from_iter(struct dax_device *dax_dev, pgoff_t pgoff,
		void *addr, size_t bytes, struct iov_iter *i);
void pmem_dax_flush(struct dax_device *dax_dev, pgoff_t pgoff,
		void *addr, size_t size);
long __pmem_direct_access(struct pmem_device *pmem, pgoff_t pgoff,
		long nr_pages, void **kaddr, pfn_t *pfn);
int nd_pmem_remove(struct device *dev);
void nd_pmem_shutdown(struct device *dev);
int pmem_core_remap_pages(struct device *dev,
		struct pmem_device *pmem, struct nd_namespace_common *ndns,
		struct resource *pfn_res, struct vmem_altmap *altmap);
int pmem_core_setup_disk(struct device *dev,
		struct pmem_device *pmem,
		struct nd_namespace_common *ndns,
		const struct block_device_operations *block_ops,
		const struct dax_operations *dax_ops,
		const struct attribute_group **attrib);
void pmem_core_setup_queue(struct device *dev, struct pmem_device *pmem,
		struct nd_namespace_common *ndns);
struct pmem_device *pmem_core_setup_pmem(struct device *dev,
		struct nd_namespace_common *ndns, struct resource *pfn_res,
		struct vmem_altmap *altmap);
#endif /* __NVDIMM_PMEM_H__ */
