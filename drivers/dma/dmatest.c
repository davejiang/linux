/*
 * DMA Engine test module
 *
 * Copyright (C) 2007 Atmel Corporation
 * Copyright (C) 2013 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/crc-t10dif.h>
#include <asm/unaligned.h>

static unsigned int test_buf_size = 16384;
module_param(test_buf_size, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(test_buf_size, "Size of the memcpy test buffer");

static char test_channel[20];
module_param_string(channel, test_channel, sizeof(test_channel),
		S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(channel, "Bus ID of the channel to test (default: any)");

static char test_device[32];
module_param_string(device, test_device, sizeof(test_device),
		S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(device, "Bus ID of the DMA Engine to test (default: any)");

static unsigned int threads_per_chan = 1;
module_param(threads_per_chan, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(threads_per_chan,
		"Number of threads to start per channel (default: 1)");

static unsigned int max_channels;
module_param(max_channels, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(max_channels,
		"Maximum number of channels to use (default: all)");

static unsigned int iterations;
module_param(iterations, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(iterations,
		"Iterations before stopping test (default: infinite)");

static unsigned int sg_buffers = 1;
module_param(sg_buffers, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(sg_buffers,
		"Number of scatter gather buffers (default: 1)");

static unsigned int dmatest;
module_param(dmatest, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dmatest,
		"dmatest 0-memcpy 1-slave_sg (default: 0)");

static unsigned int xor_sources = 3;
module_param(xor_sources, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(xor_sources,
		"Number of xor source buffers (default: 3)");

static unsigned int pq_sources = 3;
module_param(pq_sources, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pq_sources,
		"Number of p+q source buffers (default: 3)");

static int timeout = 3000;
module_param(timeout, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(timeout, "Transfer Timeout in msec (default: 3000), "
		 "Pass -1 for infinite timeout");

static bool noverify;
module_param(noverify, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(noverify, "Disable random data setup and verification");

static bool verbose;
module_param(verbose, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(verbose, "Enable \"success\" result messages (default: off)");

static unsigned int dif_blk_sz = 512;
module_param(dif_blk_sz, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dif_blk_sz, "Size of blocks in bytes for DIF operations (default: 512)");

static unsigned int dif_app_tag = 0x1234;
module_param(dif_app_tag, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dif_app_tag, "Application tag seed for DIF operations (default: 0x1234)");

static unsigned int dif_ref_tag = 0x56789ABC;
module_param(dif_ref_tag, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dif_ref_tag, "Reference tag seed for DIF operations (default: 0x56789ABC)");

/**
 * struct dmatest_params - test parameters.
 * @buf_size:		size of the memcpy test buffer
 * @channel:		bus ID of the channel to test
 * @device:		bus ID of the DMA Engine to test
 * @threads_per_chan:	number of threads to start per channel
 * @max_channels:	maximum number of channels to use
 * @iterations:		iterations before stopping test
 * @xor_sources:	number of xor source buffers
 * @pq_sources:		number of p+q source buffers
 * @timeout:		transfer timeout in msec, -1 for infinite timeout
 * @dif_blk_sz:		size of blocks for DIF operations
 * @dif_app_tag:	application tag seed for DIF operations
 * @dif_ref_tag:	reference tag seed for DIF operations
 */
struct dmatest_params {
	unsigned int	buf_size;
	char		channel[20];
	char		device[32];
	unsigned int	threads_per_chan;
	unsigned int	max_channels;
	unsigned int	iterations;
	unsigned int	xor_sources;
	unsigned int	pq_sources;
	int		timeout;
	bool		noverify;
	unsigned int	dif_blk_sz;
	u16		dif_app_tag;
	u32		dif_ref_tag;
};

/**
 * struct dmatest_info - test information.
 * @params:		test parameters
 * @lock:		access protection to the fields of this structure
 */
static struct dmatest_info {
	/* Test parameters */
	struct dmatest_params	params;

	/* Internal state */
	struct list_head	channels;
	unsigned int		nr_channels;
	struct mutex		lock;
	bool			did_init;
} test_info = {
	.channels = LIST_HEAD_INIT(test_info.channels),
	.lock = __MUTEX_INITIALIZER(test_info.lock),
};

static int dmatest_run_set(const char *val, const struct kernel_param *kp);
static int dmatest_run_get(char *val, const struct kernel_param *kp);
static const struct kernel_param_ops run_ops = {
	.set = dmatest_run_set,
	.get = dmatest_run_get,
};
static bool dmatest_run;
module_param_cb(run, &run_ops, &dmatest_run, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(run, "Run the test (default: false)");

/* Maximum amount of mismatched bytes in buffer to print */
#define MAX_ERROR_COUNT		32

/*
 * Initialization patterns. All bytes in the source buffer has bit 7
 * set, all bytes in the destination buffer has bit 7 cleared.
 *
 * Bit 6 is set for all bytes which are to be copied by the DMA
 * engine. Bit 5 is set for all bytes which are to be overwritten by
 * the DMA engine.
 *
 * The remaining bits are the inverse of a counter which increments by
 * one for each byte address.
 */
#define PATTERN_SRC		0x80
#define PATTERN_DST		0x00
#define PATTERN_COPY		0x40
#define PATTERN_OVERWRITE	0x20
#define PATTERN_COUNT_MASK	0x1f

struct dmatest_thread {
	struct list_head	node;
	struct dmatest_info	*info;
	struct task_struct	*task;
	struct dma_chan		*chan;
	u8			**srcs;
	u8			**usrcs;
	u8			**dsts;
	u8			**udsts;
	enum dma_transaction_type type;
	bool			done;
};

struct dmatest_chan {
	struct list_head	node;
	struct dma_chan		*chan;
	struct list_head	threads;
};

static DECLARE_WAIT_QUEUE_HEAD(thread_wait);
static bool wait;

static bool is_threaded_test_run(struct dmatest_info *info)
{
	struct dmatest_chan *dtc;

	list_for_each_entry(dtc, &info->channels, node) {
		struct dmatest_thread *thread;

		list_for_each_entry(thread, &dtc->threads, node) {
			if (!thread->done)
				return true;
		}
	}

	return false;
}

static int dmatest_wait_get(char *val, const struct kernel_param *kp)
{
	struct dmatest_info *info = &test_info;
	struct dmatest_params *params = &info->params;

	if (params->iterations)
		wait_event(thread_wait, !is_threaded_test_run(info));
	wait = true;
	return param_get_bool(val, kp);
}

static const struct kernel_param_ops wait_ops = {
	.get = dmatest_wait_get,
	.set = param_set_bool,
};
module_param_cb(wait, &wait_ops, &wait, S_IRUGO);
MODULE_PARM_DESC(wait, "Wait for tests to complete (default: false)");

static bool dmatest_match_channel(struct dmatest_params *params,
		struct dma_chan *chan)
{
	if (params->channel[0] == '\0')
		return true;
	return strcmp(dma_chan_name(chan), params->channel) == 0;
}

static bool dmatest_match_device(struct dmatest_params *params,
		struct dma_device *device)
{
	if (params->device[0] == '\0')
		return true;
	return strcmp(dev_name(device->dev), params->device) == 0;
}

static unsigned long dmatest_random(void)
{
	unsigned long buf;

	prandom_bytes(&buf, sizeof(buf));
	return buf;
}

static void dmatest_init_srcs(u8 **bufs, unsigned int start, unsigned int len,
		unsigned int buf_size)
{
	unsigned int i;
	u8 *buf;

	for (; (buf = *bufs); bufs++) {
		for (i = 0; i < start; i++)
			buf[i] = PATTERN_SRC | (~i & PATTERN_COUNT_MASK);
		for ( ; i < start + len; i++)
			buf[i] = PATTERN_SRC | PATTERN_COPY
				| (~i & PATTERN_COUNT_MASK);
		for ( ; i < buf_size; i++)
			buf[i] = PATTERN_SRC | (~i & PATTERN_COUNT_MASK);
		buf++;
	}
}

static void dmatest_init_dif_srcs(u8 **bufs, unsigned int start,
		unsigned int len, unsigned int buf_size,
		unsigned int block_size, u16 app_tag, u32 ref_tag)
{
	unsigned int i, j, b;
	unsigned num_blocks, block_offset, dif_offset;
	u8 *buf;
	u16 crc;

	num_blocks = len / (block_size + 8);

	for (; (buf = *bufs); bufs++) {
		for (i = 0; i < start; i++)
			buf[i] = PATTERN_SRC | (~i & PATTERN_COUNT_MASK);

		for (b = 0; b < num_blocks; b++) {
			block_offset = start + b * (block_size + 8);
			for (j = 0; j < block_size; i++, j++)
				buf[block_offset + j] = PATTERN_SRC | PATTERN_COPY
						      | (~i & PATTERN_COUNT_MASK);

			dif_offset = block_offset + block_size;

			crc = crc_t10dif(&buf[block_offset], block_size);

			put_unaligned_be16(crc, &buf[dif_offset]);
			put_unaligned_be16(app_tag, &buf[dif_offset + 2]);
			put_unaligned_be32(ref_tag, &buf[dif_offset + 4]);

			ref_tag++;
		}

		for (j = i + num_blocks * 8; j < buf_size; i++, j++)
			buf[j] = PATTERN_SRC | (~i & PATTERN_COUNT_MASK);
		buf++;
	}
}

static void dmatest_init_dsts(u8 **bufs, unsigned int start, unsigned int len,
		unsigned int buf_size)
{
	unsigned int i;
	u8 *buf;

	for (; (buf = *bufs); bufs++) {
		for (i = 0; i < start; i++)
			buf[i] = PATTERN_DST | (~i & PATTERN_COUNT_MASK);
		for ( ; i < start + len; i++)
			buf[i] = PATTERN_DST | PATTERN_OVERWRITE
				| (~i & PATTERN_COUNT_MASK);
		for ( ; i < buf_size; i++)
			buf[i] = PATTERN_DST | (~i & PATTERN_COUNT_MASK);
	}
}

static void dmatest_mismatch(u8 actual, u8 pattern, unsigned int index,
		unsigned int counter, bool is_srcbuf)
{
	u8		diff = actual ^ pattern;
	u8		expected = pattern | (~counter & PATTERN_COUNT_MASK);
	const char	*thread_name = current->comm;

	if (is_srcbuf)
		pr_warn("%s: srcbuf[0x%x] overwritten! Expected %02x, got %02x\n",
			thread_name, index, expected, actual);
	else if ((pattern & PATTERN_COPY)
			&& (diff & (PATTERN_COPY | PATTERN_OVERWRITE)))
		pr_warn("%s: dstbuf[0x%x] not copied! Expected %02x, got %02x\n",
			thread_name, index, expected, actual);
	else if (diff & PATTERN_SRC)
		pr_warn("%s: dstbuf[0x%x] was copied! Expected %02x, got %02x\n",
			thread_name, index, expected, actual);
	else
		pr_warn("%s: dstbuf[0x%x] mismatch! Expected %02x, got %02x\n",
			thread_name, index, expected, actual);
}

static unsigned int dmatest_verify(u8 **bufs, unsigned int start,
		unsigned int end, unsigned int counter, u8 pattern,
		bool is_srcbuf)
{
	unsigned int i;
	unsigned int error_count = 0;
	u8 actual;
	u8 expected;
	u8 *buf;
	unsigned int counter_orig = counter;

	for (; (buf = *bufs); bufs++) {
		counter = counter_orig;
		for (i = start; i < end; i++) {
			actual = buf[i];
			expected = pattern | (~counter & PATTERN_COUNT_MASK);
			if (actual != expected) {
				if (error_count < MAX_ERROR_COUNT)
					dmatest_mismatch(actual, pattern, i,
							 counter, is_srcbuf);
				error_count++;
			}
			counter++;
		}
	}

	if (error_count > MAX_ERROR_COUNT)
		pr_warn("%s: %u errors suppressed\n",
			current->comm, error_count - MAX_ERROR_COUNT);

	return error_count;
}

static void dmatest_dif_mismatch(const char *field_name, unsigned int actual, unsigned int expected,
		unsigned int index, bool is_srcbuf)
{
	const char *thread_name = current->comm;

	pr_warn("%s: %s block 0x%x %s mismatch! Expected %x, got %x\n",
		thread_name, is_srcbuf ? "src" : "dst", index, field_name, expected, actual);
}

static unsigned int dmatest_dif_verify(u8 *buf, unsigned int blk_sz,
				       unsigned int start, unsigned int end,
				       unsigned int counter, u8 pattern,
				       bool is_srcbuf,
				       u16 expected_app_tag, u32 expected_ref_tag)
{
	unsigned int b, i;
	unsigned int error_count = 0;
	u8 actual;
	u8 expected;
	unsigned int num_blocks;
	unsigned int block_offset, dif_offset;
	u16 expected_crc;
	u16 buf_crc;
	u16 buf_app_tag;
	u32 buf_ref_tag;

	num_blocks = (end - start) / (blk_sz + 8);

	for (b = 0; b < num_blocks; b++) {
		block_offset = start + b * (blk_sz + 8);
		for (i = 0; i < blk_sz; i++) {
			actual = buf[block_offset + i];
			expected = pattern | (~counter & PATTERN_COUNT_MASK);
			if (actual != expected) {
				if (error_count < MAX_ERROR_COUNT)
					dmatest_mismatch(actual, pattern,
							 block_offset + i,
							 counter, is_srcbuf);
				error_count++;
			}
			counter++;
		}

		dif_offset = block_offset + blk_sz;
		buf_crc = get_unaligned_be16(&buf[dif_offset]);
		buf_app_tag = get_unaligned_be16(&buf[dif_offset + 2]);
		buf_ref_tag = get_unaligned_be32(&buf[dif_offset + 4]);

		expected_crc = crc_t10dif(&buf[block_offset], blk_sz);
		if (buf_crc != expected_crc) {
			if (error_count < MAX_ERROR_COUNT)
				dmatest_dif_mismatch("CRC", buf_crc, expected_crc,
						     b, is_srcbuf);
			error_count++;
		}
		if (buf_app_tag != expected_app_tag) {
			if (error_count < MAX_ERROR_COUNT)
				dmatest_dif_mismatch("app tag", buf_app_tag, expected_app_tag,
						     b, is_srcbuf);
			error_count++;
		}
		if (buf_ref_tag != expected_ref_tag) {
			if (error_count < MAX_ERROR_COUNT)
				dmatest_dif_mismatch("ref tag", buf_ref_tag, expected_ref_tag,
						     b, is_srcbuf);
			error_count++;
		}

		expected_ref_tag++;
	}

	if (error_count > MAX_ERROR_COUNT)
		pr_warn("%s: %u errors suppressed\n",
			current->comm, error_count - MAX_ERROR_COUNT);

	return error_count;
}

/* poor man's completion - we want to use wait_event_freezable() on it */
struct dmatest_done {
	bool			done;
	wait_queue_head_t	*wait;
};

static void dmatest_callback(void *arg)
{
	struct dmatest_done *done = arg;

	done->done = true;
	wake_up_all(done->wait);
}

static unsigned int min_odd(unsigned int x, unsigned int y)
{
	unsigned int val = min(x, y);

	return val % 2 ? val : val - 1;
}

static void result(const char *err, unsigned int n, unsigned int src_off,
		   unsigned int dst_off, unsigned int len, unsigned long data)
{
	pr_info("%s: result #%u: '%s' with src_off=0x%x dst_off=0x%x len=0x%x (%lu)\n",
		current->comm, n, err, src_off, dst_off, len, data);
}

static void dbg_result(const char *err, unsigned int n, unsigned int src_off,
		       unsigned int dst_off, unsigned int len,
		       unsigned long data)
{
	pr_debug("%s: result #%u: '%s' with src_off=0x%x dst_off=0x%x len=0x%x (%lu)\n",
		 current->comm, n, err, src_off, dst_off, len, data);
}

#define verbose_result(err, n, src_off, dst_off, len, data) ({	\
	if (verbose)						\
		result(err, n, src_off, dst_off, len, data);	\
	else							\
		dbg_result(err, n, src_off, dst_off, len, data);\
})

static unsigned long long dmatest_persec(s64 runtime, unsigned int val)
{
	unsigned long long per_sec = 1000000;

	if (runtime <= 0)
		return 0;

	/* drop precision until runtime is 32-bits */
	while (runtime > UINT_MAX) {
		runtime >>= 1;
		per_sec <<= 1;
	}

	per_sec *= val;
	do_div(per_sec, runtime);
	return per_sec;
}

static unsigned long long dmatest_KBs(s64 runtime, unsigned long long len)
{
	return dmatest_persec(runtime, len >> 10);
}

/*
 * This function repeatedly tests DMA transfers of various lengths and
 * offsets for a given operation type until it is told to exit by
 * kthread_stop(). There may be multiple threads running this function
 * in parallel for a single channel, and there may be multiple channels
 * being tested in parallel.
 *
 * Before each test, the source and destination buffer is initialized
 * with a known pattern. This pattern is different depending on
 * whether it's in an area which is supposed to be copied or
 * overwritten, and different in the source and destination buffers.
 * So if the DMA engine doesn't copy exactly what we tell it to copy,
 * we'll notice.
 */
static int dmatest_func(void *data)
{
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(done_wait);
	struct dmatest_thread	*thread = data;
	struct dmatest_done	done = { .wait = &done_wait };
	struct dmatest_info	*info;
	struct dmatest_params	*params;
	struct dma_chan		*chan;
	struct dma_device	*dev;
	unsigned int		src_len, dst_len;
	unsigned int		data_len;
	unsigned int		error_count = 0;
	unsigned int		failed_tests = 0;
	unsigned int		total_tests = 0;
	dma_cookie_t		cookie;
	enum dma_status		status;
	enum dma_ctrl_flags	flags;
	u8			*pq_coefs = NULL;
	int			ret;
	int			src_cnt;
	int			dst_cnt;
	int			buf_size;
	int			i;
	ktime_t			ktime, start, diff;
	ktime_t			filltime = 0;
	ktime_t			comparetime = 0;
	s64			runtime = 0;
	unsigned long long	total_len = 0;
	enum sum_check_flags	difres = 0;
	u8 align=0;
	set_freezable();

	ret = -ENOMEM;

	smp_rmb();
	info = thread->info;
	params = &info->params;
	chan = thread->chan;
	dev = chan->device;

	if (thread->type == DMA_MEMCPY) {
		align = dev->copy_align;
		src_cnt = dst_cnt = 1;
		buf_size = params->buf_size;
	} else if (thread->type == DMA_SG){
		align = dev->copy_align;
		src_cnt = dst_cnt = sg_buffers;
		buf_size = params->buf_size;
	} else if (thread->type == DMA_XOR) {
		/* force odd to ensure dst = src */
		src_cnt = min_odd(params->xor_sources | 1, dev->max_xor);
		dst_cnt = 1;
		buf_size = params->buf_size;
		align = dev->xor_align;
	} else if (thread->type == DMA_PQ) {
		/* force odd to ensure dst = src */
		src_cnt = min_odd(params->pq_sources | 1, dma_maxpq(dev, 0));
		dst_cnt = 2;
		buf_size = params->buf_size;
		align = dev->pq_align;
		pq_coefs = kmalloc(params->pq_sources+1, GFP_KERNEL);
		if (!pq_coefs)
			goto err_thread_type;

		for (i = 0; i < src_cnt; i++)
			pq_coefs[i] = 1;
	} else if (thread->type == DMA_DIF_INSERT ||
		   thread->type == DMA_DIF_STRIP ||
		   thread->type == DMA_DIF_UPDATE) {
		if (params->buf_size < params->dif_blk_sz) {
			pr_err("test_buf_size must be >= dif_blk_sz\n");
			goto err_thread_type;
		}
		src_cnt = dst_cnt = 1;
		buf_size = params->buf_size + (params->buf_size /
					       params->dif_blk_sz) * 8;
	} else if (thread->type == DMA_MCAST) {
		align = dev->copy_align;
		src_cnt = 1;
		dst_cnt = 2;
		buf_size = params->buf_size;
	} else
		goto err_thread_type;

	thread->srcs = kcalloc(src_cnt + 1, sizeof(u8 *), GFP_KERNEL);
	if (!thread->srcs)
		goto err_srcs;

	thread->usrcs = kcalloc(src_cnt + 1, sizeof(u8 *), GFP_KERNEL);
	if (!thread->usrcs)
		goto err_usrcs;

	for (i = 0; i < src_cnt; i++) {
		thread->usrcs[i] = kmalloc(buf_size + align,
					   GFP_KERNEL);
		if (!thread->usrcs[i])
			goto err_srcbuf;

		/* align srcs to alignment restriction */
		if (align)
			thread->srcs[i] = PTR_ALIGN(thread->usrcs[i], align);
		else
			thread->srcs[i] = thread->usrcs[i];
	}
	thread->srcs[i] = NULL;

	thread->dsts = kcalloc(dst_cnt + 1, sizeof(u8 *), GFP_KERNEL);
	if (!thread->dsts)
		goto err_dsts;

	thread->udsts = kcalloc(dst_cnt + 1, sizeof(u8 *), GFP_KERNEL);
	if (!thread->udsts)
		goto err_udsts;

	for (i = 0; i < dst_cnt; i++) {
		thread->udsts[i] = kmalloc(buf_size + align,
					   GFP_KERNEL);
		if (!thread->udsts[i])
			goto err_dstbuf;

		/* align dsts to alignment restriction */
		if (align)
			thread->dsts[i] = PTR_ALIGN(thread->udsts[i], align);
		else
			thread->dsts[i] = thread->udsts[i];
	}
	thread->dsts[i] = NULL;
	set_user_nice(current, 10);

	/*
	 * src and dst buffers are freed by ourselves below
	 */
	flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT;

	ktime = ktime_get();
	while (!kthread_should_stop()
	       && !(params->iterations && total_tests >= params->iterations)) {
		struct dma_async_tx_descriptor *tx = NULL;
		struct dmaengine_unmap_data *um;
		dma_addr_t srcs[src_cnt];
		dma_addr_t *dsts;
		unsigned int src_off, dst_off, len = 0;
		unsigned int blk_sz;
		struct scatterlist tx_sg[src_cnt];
		struct scatterlist rx_sg[src_cnt];


		/* Check if buffer count fits into map count variable (u8) */
		if ((src_cnt + dst_cnt) >= 255) {
			pr_err("too many buffers (%d of 255 supported)\n",
			       src_cnt + dst_cnt);
			break;
		}

		if (1 << align > params->buf_size) {
			pr_err("%u-byte buffer too small for %d-byte alignment\n",
			       buf_size, 1 << align);
			break;
		}

		/* honor block size restrictions */
		blk_sz = 1 << align;
		if (thread->type == DMA_DIF_INSERT ||
		    thread->type == DMA_DIF_STRIP ||
		    thread->type == DMA_DIF_UPDATE)
			blk_sz = params->dif_blk_sz;

		if( params->noverify)
			data_len = params->buf_size;
		else {
			data_len = dmatest_random() % params->buf_size + 1;
			//data_len -= (data_len % blk_sz);
		}

		data_len = (data_len >> align) << align;


		if (thread->type == DMA_DIF_INSERT ||
		    thread->type == DMA_DIF_STRIP ||
		    thread->type == DMA_DIF_UPDATE)
			data_len = params->buf_size;


		if (!data_len)
			data_len = blk_sz;

		total_len += data_len;
		src_len = data_len;
		if (thread->type == DMA_DIF_INSERT ||
		    thread->type == DMA_DIF_UPDATE)
			dst_len += ((dst_len / blk_sz) * 8);

		dst_len = data_len;
		if (thread->type == DMA_DIF_STRIP ||
		    thread->type == DMA_DIF_UPDATE)
			src_len += ((src_len / blk_sz) * 8);

		if (!(thread->type == DMA_DIF_INSERT ||
		    thread->type == DMA_DIF_STRIP ||
		    thread->type == DMA_DIF_UPDATE))
		{
			src_len = data_len;
			dst_len = data_len;
		}
		if (params->noverify) {
			src_off = 0;
			dst_off = 0;
		} else {
			src_off = dmatest_random() % (buf_size - src_len + 1);
			dst_off = dmatest_random() % (buf_size - dst_len + 1);
			src_off = (src_off >> align) << align;
			dst_off = (dst_off >> align) << align;
		}
		if (thread->type == DMA_DIF_STRIP ||
				thread->type == DMA_DIF_UPDATE) {
				dmatest_init_dif_srcs(thread->srcs, src_off, src_len,
							  buf_size, blk_sz,
							  params->dif_app_tag, params->dif_ref_tag);
		} else {
				dmatest_init_srcs(thread->srcs, src_off, src_len,
						  buf_size);
		}
		dmatest_init_dsts(thread->dsts, dst_off, dst_len,buf_size);
		diff = ktime_sub(ktime_get(), start);
		filltime = ktime_add(filltime, diff);
		um = dmaengine_get_unmap_data(dev->dev, src_cnt+dst_cnt,
					      GFP_KERNEL);
		if (!um) {
			failed_tests++;
			result("unmap data NULL", total_tests,
			       src_off, dst_off, data_len, ret);
			continue;
		}

		um->len = buf_size;
		for (i = 0; i < src_cnt; i++) {
			void *buf = thread->srcs[i];
			struct page *pg = virt_to_page(buf);
			unsigned long pg_off = offset_in_page(buf);

			um->addr[i] = dma_map_page(dev->dev, pg, pg_off,
						   um->len, DMA_TO_DEVICE);
			srcs[i] = um->addr[i] + src_off;
			ret = dma_mapping_error(dev->dev, um->addr[i]);
			if (ret) {
				dmaengine_unmap_put(um);
				result("src mapping error", total_tests,
				       src_off, dst_off, data_len, ret);
				failed_tests++;
				continue;
			}
			um->to_cnt++;
		}
		/* map with DMA_BIDIRECTIONAL to force writeback/invalidate */
		dsts = &um->addr[src_cnt];
		for (i = 0; i < dst_cnt; i++) {
			void *buf = thread->dsts[i];
			struct page *pg = virt_to_page(buf);
			unsigned long pg_off = offset_in_page(buf);

			dsts[i] = dma_map_page(dev->dev, pg, pg_off, um->len,
					       DMA_BIDIRECTIONAL);
			ret = dma_mapping_error(dev->dev, dsts[i]);
			if (ret) {
				dmaengine_unmap_put(um);
				result("dst mapping error", total_tests,
				       src_off, dst_off, dst_len, ret);
				failed_tests++;
				continue;
			}
			um->bidi_cnt++;
		}

		sg_init_table(tx_sg, src_cnt);
		sg_init_table(rx_sg, src_cnt);
		for (i = 0; i < src_cnt; i++) {
			sg_dma_address(&rx_sg[i]) = srcs[i];
			sg_dma_address(&tx_sg[i]) = dsts[i] + dst_off;
			sg_dma_len(&tx_sg[i]) = len;
			sg_dma_len(&rx_sg[i]) = len;
		}

		if (thread->type == DMA_MEMCPY)
			tx = dev->device_prep_dma_memcpy(chan,
							 dsts[0] + dst_off,
							 srcs[0], data_len, flags);
		else if (thread->type == DMA_SG)
			tx = dev->device_prep_dma_sg(chan, tx_sg, src_cnt,
						     rx_sg, src_cnt, flags);
		else if (thread->type == DMA_XOR)
			tx = dev->device_prep_dma_xor(chan,
						      dsts[0] + dst_off,
						      srcs, src_cnt,
					              data_len, flags);
		else if (thread->type == DMA_PQ) {
			dma_addr_t dma_pq[dst_cnt];

			for (i = 0; i < dst_cnt; i++)
				dma_pq[i] = dsts[i] + dst_off;
			tx = dev->device_prep_dma_pq(chan, dma_pq, srcs,
						     src_cnt, pq_coefs,
						     data_len, flags);
		} else if (thread->type == DMA_DIF_INSERT) {
		        tx = dev->device_prep_dma_dif_insert(chan,
							     params->dif_blk_sz,
							     srcs[0],
							     dsts[0] + dst_off,
							     data_len,
							     params->dif_app_tag, params->dif_ref_tag,
							     0,
							     flags);
		} else if (thread->type == DMA_DIF_STRIP) {
			tx = dev->device_prep_dma_dif_strip(chan,
							    params->dif_blk_sz,
							    srcs[0],
							    dsts[0] + dst_off,
							    src_len,
							    params->dif_app_tag, params->dif_ref_tag,
							    &difres,
							    0,
							    flags);
		} else if (thread->type == DMA_DIF_UPDATE) {
			tx = dev->device_prep_dma_dif_update(chan,
							     params->dif_blk_sz,
							     srcs[0],
							     dsts[0] + dst_off,
							     src_len,
							     params->dif_app_tag, params->dif_ref_tag,
							     params->dif_app_tag, params->dif_ref_tag,
							     &difres,
							     0,
							     flags);
		}
		else if (thread->type == DMA_MCAST) {
			dma_addr_t dma_mcast[dst_cnt];
			for (i = 0; i < dst_cnt; i++)
				dma_mcast[i] = dsts[i] + dst_off;
			tx = dev->device_prep_dma_mcast(chan,
							dma_mcast,
							2,
							srcs[0],
							data_len,
							flags);
		}

		if (!tx) {
			dmaengine_unmap_put(um);
			result("prep error", total_tests, src_off,
			       dst_off, data_len, ret);
			msleep(100);
			failed_tests++;
			continue;
		}

		done.done = false;
		tx->callback = dmatest_callback;
		tx->callback_param = &done;
		cookie = tx->tx_submit(tx);

		if (dma_submit_error(cookie)) {
			dmaengine_unmap_put(um);
			result("submit error", total_tests, src_off,
			       dst_off, data_len, ret);
			msleep(100);
			failed_tests++;
			continue;
		}
		dma_async_issue_pending(chan);

		wait_event_freezable_timeout(done_wait, done.done,
					     msecs_to_jiffies(params->timeout));

		status = dma_async_is_tx_complete(chan, cookie, NULL, NULL);

		if (!done.done) {
			/*
			 * We're leaving the timed out dma operation with
			 * dangling pointer to done_wait.  To make this
			 * correct, we'll need to allocate wait_done for
			 * each test iteration and perform "who's gonna
			 * free it this time?" dancing.  For now, just
			 * leave it dangling.
			 */
			dmaengine_unmap_put(um);
			result("test timed out", total_tests, src_off, dst_off,
			       data_len, 0);
			failed_tests++;
			continue;
		} else if (status != DMA_COMPLETE) {
			dmaengine_unmap_put(um);
			result(status == DMA_ERROR ?
			       "completion error status" :
			       "completion busy status", total_tests, src_off,
			       dst_off, data_len, ret);
			failed_tests++;
			continue;
		}

		dmaengine_unmap_put(um);

		if (params->noverify) {
			verbose_result("test passed", total_tests, src_off,
				       dst_off, data_len, 0);
			continue;
		}

		start = ktime_get();
		pr_info("%s: verifying source buffer...\n", current->comm);
		if (thread->type == DMA_DIF_STRIP ||
		    thread->type == DMA_DIF_UPDATE) {
			error_count += dmatest_dif_verify(thread->srcs[0],
					params->dif_blk_sz,
					src_off,
					src_off + src_len, src_off,
				        PATTERN_SRC | PATTERN_COPY, true,
					params->dif_app_tag, params->dif_ref_tag);
		} else {
			error_count = dmatest_verify(thread->srcs, 0, src_off,
						     0, PATTERN_SRC, true);
			error_count += dmatest_verify(thread->srcs, src_off,
						      src_off + data_len,
						      src_off,
						      PATTERN_SRC | PATTERN_COPY,
						      true);
			error_count += dmatest_verify(thread->srcs,
						      src_off + data_len,
						      buf_size,
						      src_off + data_len,
						      PATTERN_SRC, true);
		}
		pr_info("%s: verifying dest buffer...\n", current->comm);
		if (thread->type == DMA_DIF_INSERT ||
		    thread->type == DMA_DIF_UPDATE) {
			error_count += dmatest_dif_verify(thread->dsts[0],
					params->dif_blk_sz,
					dst_off,
					dst_off + dst_len, src_off,
				        PATTERN_SRC | PATTERN_COPY, false,
					params->dif_app_tag, params->dif_ref_tag);
		} else {
			error_count += dmatest_verify(thread->dsts, 0, dst_off,
					0, PATTERN_DST, false);
			error_count += dmatest_verify(thread->dsts, dst_off,
					dst_off + data_len, src_off,
					PATTERN_SRC | PATTERN_COPY, false);
			error_count += dmatest_verify(thread->dsts,
					dst_off + data_len,
					buf_size, dst_off + data_len,
					PATTERN_DST, false);
		}

		diff = ktime_sub( ktime_get(), start );
		comparetime = ktime_add( comparetime, diff );
		if (thread->type == DMA_DIF_STRIP ||
		    thread->type == DMA_DIF_UPDATE) {
			if (difres & DIF_CHECK_GUARD_RESULT) {
				pr_info("%s: DIF CRC error\n", current->comm);
				error_count++;
			}
			if (difres & DIF_CHECK_APP_RESULT) {
				pr_info("%s: DIF app tag error\n", current->comm);
				error_count++;
			}
			if (difres & DIF_CHECK_REF_RESULT) {
				pr_info("%s: DIF ref tag error\n", current->comm);
				error_count++;
			}
		}

		if (error_count) {
			result("data error", total_tests, src_off, dst_off,
			       data_len, error_count);
			failed_tests++;
		} else {
			verbose_result("test passed", total_tests, src_off,
				       dst_off, data_len, 0);
		}
	}
	runtime = ktime_us_delta(ktime_get(), ktime);
	ret = 0;
err_dstbuf:
	for (i = 0; thread->udsts[i]; i++)
		kfree(thread->udsts[i]);
	kfree(thread->udsts);
err_udsts:
	kfree(thread->dsts);
err_dsts:
err_srcbuf:
	for (i = 0; thread->usrcs[i]; i++)
		kfree(thread->usrcs[i]);
	kfree(thread->usrcs);
err_usrcs:
	kfree(thread->srcs);
err_srcs:
	kfree(pq_coefs);
err_thread_type:
	pr_info("%s: summary %u tests, %u failures %llu iops %llu KB/s (%d)\n",
		current->comm, total_tests, failed_tests,
		dmatest_persec(runtime, total_tests),
		dmatest_KBs(runtime, total_len), ret);

	/* terminate all transfers on specified channels */
	if (ret)
		dmaengine_terminate_all(chan);

	thread->done = true;
	wake_up(&thread_wait);

	return ret;
}

static void dmatest_cleanup_channel(struct dmatest_chan *dtc)
{
	struct dmatest_thread	*thread;
	struct dmatest_thread	*_thread;
	int			ret;

	list_for_each_entry_safe(thread, _thread, &dtc->threads, node) {
		ret = kthread_stop(thread->task);
		pr_debug("thread %s exited with status %d\n",
			 thread->task->comm, ret);
		list_del(&thread->node);
		put_task_struct(thread->task);
		kfree(thread);
	}

	/* terminate all transfers on specified channels */
	dmaengine_terminate_all(dtc->chan);

	kfree(dtc);
}

static int dmatest_add_threads(struct dmatest_info *info,
		struct dmatest_chan *dtc, enum dma_transaction_type type)
{
	struct dmatest_params *params = &info->params;
	struct dmatest_thread *thread;
	struct dma_chan *chan = dtc->chan;
	char *op;
	unsigned int i;

	if (type == DMA_MEMCPY)
		op = "copy";
	else if (type == DMA_SG)
		op = "sg";
	else if (type == DMA_XOR)
		op = "xor";
	else if (type == DMA_PQ)
		op = "pq";
	else if (type == DMA_DIF_INSERT)
		op = "dif_insert";
	else if (type == DMA_DIF_STRIP)
		op = "dif_strip";
	else if (type == DMA_DIF_UPDATE)
		op = "dif_update";
	else if (type == DMA_MCAST)
		op = "mcast";
	else
		return -EINVAL;

	for (i = 0; i < params->threads_per_chan; i++) {
		thread = kzalloc(sizeof(struct dmatest_thread), GFP_KERNEL);
		if (!thread) {
			pr_warn("No memory for %s-%s%u\n",
				dma_chan_name(chan), op, i);
			break;
		}
		thread->info = info;
		thread->chan = dtc->chan;
		thread->type = type;
		smp_wmb();
		thread->task = kthread_create(dmatest_func, thread, "%s-%s%u",
				dma_chan_name(chan), op, i);
		if (IS_ERR(thread->task)) {
			pr_warn("Failed to create thread %s-%s%u\n",
				dma_chan_name(chan), op, i);
			kfree(thread);
			break;
		}

		/* srcbuf and dstbuf are allocated by the thread itself */
		get_task_struct(thread->task);
		list_add_tail(&thread->node, &dtc->threads);
		wake_up_process(thread->task);
	}

	return i;
}

static int dmatest_add_channel(struct dmatest_info *info,
		struct dma_chan *chan)
{
	struct dmatest_chan	*dtc;
	struct dma_device	*dma_dev = chan->device;
	unsigned int		thread_count = 0;
	int cnt;

	dtc = kmalloc(sizeof(struct dmatest_chan), GFP_KERNEL);
	if (!dtc) {
		pr_warn("No memory for %s\n", dma_chan_name(chan));
		return -ENOMEM;
	}

	dtc->chan = chan;
	INIT_LIST_HEAD(&dtc->threads);

	if (dma_has_cap(DMA_MEMCPY, dma_dev->cap_mask)) {
		if (dmatest == 0) {
			cnt = dmatest_add_threads(info, dtc, DMA_MEMCPY);
			thread_count += cnt > 0 ? cnt : 0;
		}
	}

	if (dma_has_cap(DMA_SG, dma_dev->cap_mask)) {
		if (dmatest == 1) {
			cnt = dmatest_add_threads(info, dtc, DMA_SG);
			thread_count += cnt > 0 ? cnt : 0;
		}
	}

	if (dma_has_cap(DMA_XOR, dma_dev->cap_mask)) {
		cnt = dmatest_add_threads(info, dtc, DMA_XOR);
		thread_count += cnt > 0 ? cnt : 0;
	}
	if (dma_has_cap(DMA_PQ, dma_dev->cap_mask)) {
		cnt = dmatest_add_threads(info, dtc, DMA_PQ);
		thread_count += cnt > 0 ? cnt : 0;
	}
	if (dma_has_cap(DMA_DIF_INSERT, dma_dev->cap_mask)) {
		cnt = dmatest_add_threads(info, dtc, DMA_DIF_INSERT);
		thread_count += cnt > 0 ? cnt : 0;
	}
	if (dma_has_cap(DMA_DIF_STRIP, dma_dev->cap_mask)) {
		cnt = dmatest_add_threads(info, dtc, DMA_DIF_STRIP);
		thread_count += cnt > 0 ? cnt : 0;
	}
	if (dma_has_cap(DMA_DIF_UPDATE, dma_dev->cap_mask)) {
		cnt = dmatest_add_threads(info, dtc, DMA_DIF_UPDATE);
		thread_count += cnt > 0 ? cnt : 0;
	}
	if (dma_has_cap(DMA_MCAST, dma_dev->cap_mask)) {
		if (dmatest == 0) {
			cnt = dmatest_add_threads(info, dtc, DMA_MCAST);
			thread_count += cnt > 0 ? cnt : 0;
		}
	}

	pr_info("Started %u threads using %s\n",
		thread_count, dma_chan_name(chan));

	list_add_tail(&dtc->node, &info->channels);
	info->nr_channels++;

	return 0;
}

static bool filter(struct dma_chan *chan, void *param)
{
	struct dmatest_params *params = param;

	if (!dmatest_match_channel(params, chan) ||
	    !dmatest_match_device(params, chan->device))
		return false;
	else
		return true;
}

static void request_channels(struct dmatest_info *info,
			     enum dma_transaction_type type)
{
	dma_cap_mask_t mask;

	dma_cap_zero(mask);
	dma_cap_set(type, mask);
	for (;;) {
		struct dmatest_params *params = &info->params;
		struct dma_chan *chan;

		chan = dma_request_channel(mask, filter, params);
		if (chan) {
			if (dmatest_add_channel(info, chan)) {
				dma_release_channel(chan);
				break; /* add_channel failed, punt */
			}
		} else
			break; /* no more channels available */
		if (params->max_channels &&
		    info->nr_channels >= params->max_channels)
			break; /* we have all we need */
	}
}

static void run_threaded_test(struct dmatest_info *info)
{
	struct dmatest_params *params = &info->params;

	/* Copy test parameters */
	params->buf_size = test_buf_size;
	strlcpy(params->channel, strim(test_channel), sizeof(params->channel));
	strlcpy(params->device, strim(test_device), sizeof(params->device));
	params->threads_per_chan = threads_per_chan;
	params->max_channels = max_channels;
	params->iterations = iterations;
	params->xor_sources = xor_sources;
	params->pq_sources = pq_sources;
	params->timeout = timeout;
	params->noverify = noverify;
	params->dif_blk_sz = dif_blk_sz;
	params->dif_app_tag = dif_app_tag;
	params->dif_ref_tag = dif_ref_tag;

	request_channels(info, DMA_MEMCPY);
	request_channels(info, DMA_XOR);
	request_channels(info, DMA_SG);
	request_channels(info, DMA_PQ);

	request_channels(info, DMA_DIF_INSERT);
	request_channels(info, DMA_DIF_STRIP);
	request_channels(info, DMA_DIF_UPDATE);
	request_channels(info, DMA_MCAST);
}

static void stop_threaded_test(struct dmatest_info *info)
{
	struct dmatest_chan *dtc, *_dtc;
	struct dma_chan *chan;

	list_for_each_entry_safe(dtc, _dtc, &info->channels, node) {
		list_del(&dtc->node);
		chan = dtc->chan;
		dmatest_cleanup_channel(dtc);
		pr_debug("dropped channel %s\n", dma_chan_name(chan));
		dma_release_channel(chan);
	}

	info->nr_channels = 0;
}

static void restart_threaded_test(struct dmatest_info *info, bool run)
{
	/* we might be called early to set run=, defer running until all
	 * parameters have been evaluated
	 */
	if (!info->did_init)
		return;

	/* Stop any running test first */
	stop_threaded_test(info);

	/* Run test with new parameters */
	run_threaded_test(info);
}

static int dmatest_run_get(char *val, const struct kernel_param *kp)
{
	struct dmatest_info *info = &test_info;

	mutex_lock(&info->lock);
	if (is_threaded_test_run(info)) {
		dmatest_run = true;
	} else {
		stop_threaded_test(info);
		dmatest_run = false;
	}
	mutex_unlock(&info->lock);

	return param_get_bool(val, kp);
}

static int dmatest_run_set(const char *val, const struct kernel_param *kp)
{
	struct dmatest_info *info = &test_info;
	int ret;

	mutex_lock(&info->lock);
	ret = param_set_bool(val, kp);
	if (ret) {
		mutex_unlock(&info->lock);
		return ret;
	}

	if (is_threaded_test_run(info))
		ret = -EBUSY;
	else if (dmatest_run)
		restart_threaded_test(info, dmatest_run);

	mutex_unlock(&info->lock);

	return ret;
}

static int __init dmatest_init(void)
{
	struct dmatest_info *info = &test_info;
	struct dmatest_params *params = &info->params;

	if (dmatest_run) {
		mutex_lock(&info->lock);
		run_threaded_test(info);
		mutex_unlock(&info->lock);
	}

	if (params->iterations && wait)
		wait_event(thread_wait, !is_threaded_test_run(info));

	/* module parameters are stable, inittime tests are started,
	 * let userspace take over 'run' control
	 */
	info->did_init = true;

	return 0;
}
/* when compiled-in wait for drivers to load first */
late_initcall(dmatest_init);

static void __exit dmatest_exit(void)
{
	struct dmatest_info *info = &test_info;

	mutex_lock(&info->lock);
	stop_threaded_test(info);
	mutex_unlock(&info->lock);
}
module_exit(dmatest_exit);

MODULE_AUTHOR("Haavard Skinnemoen (Atmel)");
MODULE_LICENSE("GPL v2");
