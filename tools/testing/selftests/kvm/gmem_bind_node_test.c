// SPDX-License-Identifier: GPL-2.0
/*
 * Standalone test for GUEST_MEMFD_FLAG_BIND_NODE.
 *
 * Verifies that a guest_memfd created with GUEST_MEMFD_FLAG_BIND_NODE allocates
 * its folios on the requested NUMA node, without any userspace mbind().  The
 * folio placement is checked with move_pages(2) (status query mode).
 *
 * Self-contained: issues the KVM ioctls directly so it can carry the extended
 * struct kvm_create_guest_memfd (with the node field).  Build inside the guest:
 *   gcc -O2 -o gmem_bind_node_test gmem_bind_node_test.c -lnuma
 *
 * Usage: gmem_bind_node_test <target_node>
 */
#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/kvm.h>

/* Mirror the (proposed) uapi additions in case the host headers lag. */
#ifndef GUEST_MEMFD_FLAG_BIND_NODE
#define GUEST_MEMFD_FLAG_BIND_NODE	(1ULL << 2)
#endif
#ifndef GUEST_MEMFD_FLAG_MMAP
#define GUEST_MEMFD_FLAG_MMAP		(1ULL << 0)
#endif
#ifndef GUEST_MEMFD_FLAG_INIT_SHARED
#define GUEST_MEMFD_FLAG_INIT_SHARED	(1ULL << 1)
#endif

struct gmemfd_args {
	__u64 size;
	__u64 flags;
	__u32 node;
	__u32 pad;
	__u64 reserved[5];
};

#ifndef KVM_X86_SW_PROTECTED_VM
#define KVM_X86_SW_PROTECTED_VM	1
#endif

/* True if the node has any memory (MemTotal > 0). */
static int node_has_memory(int node)
{
	char path[128];
	char line[256];
	FILE *f;
	long total = -1;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/node/node%d/meminfo", node);
	f = fopen(path, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "MemTotal:")) {
			sscanf(line, "Node %*d MemTotal: %ld kB", &total);
			break;
		}
	}
	fclose(f);
	return total > 0;
}

static long move_pages_status(void *addr)
{
	void *pages[1] = { addr };
	int status[1] = { -1 };
	long ret;

	ret = syscall(SYS_move_pages, 0, 1, pages, NULL, status, 0);
	if (ret)
		err(1, "move_pages");
	return status[0];
}

int main(int argc, char **argv)
{
	int kvm, vm, gmem, ret;
	long page_size = sysconf(_SC_PAGESIZE);
	size_t size = page_size * 4;
	int target_node;
	struct gmemfd_args ga = {};
	char *mem;
	size_t i;

	if (argc != 2)
		errx(1, "usage: %s <target_node>", argv[0]);
	target_node = atoi(argv[1]);

	kvm = open("/dev/kvm", O_RDWR);
	if (kvm < 0)
		err(1, "open /dev/kvm");

	/*
	 * Use a default (non-protected) VM: it has no private memory, so it
	 * advertises GUEST_MEMFD_FLAG_INIT_SHARED, which lets the host mmap and
	 * fault the gmem (needed to observe placement with move_pages()).  A
	 * SW-protected VM would not advertise INIT_SHARED and the host fault
	 * would SIGBUS.
	 */
	vm = ioctl(kvm, KVM_CREATE_VM, 0UL);
	if (vm < 0)
		err(1, "KVM_CREATE_VM");

	{
		long caps = ioctl(vm, KVM_CHECK_EXTENSION,
				  KVM_CAP_GUEST_MEMFD_FLAGS);

		printf("KVM_CAP_GUEST_MEMFD_FLAGS = 0x%lx\n", caps);
		if (!(caps & GUEST_MEMFD_FLAG_BIND_NODE))
			errx(1, "BIND_NODE flag not advertised");
		if (!(caps & GUEST_MEMFD_FLAG_INIT_SHARED))
			errx(1, "INIT_SHARED not advertised; cannot fault from host");
	}

	/* Negative: pad must be zero. */
	ga = (struct gmemfd_args){ .size = size,
				   .flags = GUEST_MEMFD_FLAG_BIND_NODE,
				   .node = target_node, .pad = 1 };
	ret = ioctl(vm, KVM_CREATE_GUEST_MEMFD, &ga);
	if (!(ret < 0 && errno == EINVAL))
		errx(1, "nonzero pad should be rejected (ret=%d errno=%d)", ret, errno);
	printf("OK: nonzero pad rejected\n");

	/* Negative: out-of-range node. */
	ga = (struct gmemfd_args){ .size = size,
				   .flags = GUEST_MEMFD_FLAG_BIND_NODE,
				   .node = 1 << 20 };
	ret = ioctl(vm, KVM_CREATE_GUEST_MEMFD, &ga);
	if (!(ret < 0 && errno == EINVAL))
		errx(1, "bogus node should be rejected (ret=%d errno=%d)", ret, errno);
	printf("OK: out-of-range node rejected\n");

	/*
	 * Negative: node set without the flag.  Only meaningful for a nonzero
	 * node: node 0 is indistinguishable from "node field unset".
	 */
	if (target_node != 0) {
		ga = (struct gmemfd_args){ .size = size, .flags = 0,
					   .node = target_node };
		ret = ioctl(vm, KVM_CREATE_GUEST_MEMFD, &ga);
		if (!(ret < 0 && errno == EINVAL))
			errx(1, "node without flag should be rejected (ret=%d errno=%d)",
			     ret, errno);
		printf("OK: node-without-flag rejected\n");
	}

	/* Positive: bind to target_node, mmap, fault, verify placement. */
	ga = (struct gmemfd_args){
		.size = size,
		.flags = GUEST_MEMFD_FLAG_BIND_NODE | GUEST_MEMFD_FLAG_MMAP |
			 GUEST_MEMFD_FLAG_INIT_SHARED,
		.node = target_node,
	};
	gmem = ioctl(vm, KVM_CREATE_GUEST_MEMFD, &ga);
	if (gmem < 0) {
		/*
		 * A memoryless (e.g. CPU-only) node must be rejected at create
		 * with EINVAL, not produce an opaque failure later.
		 */
		if (!node_has_memory(target_node) && errno == EINVAL) {
			printf("OK: memoryless node %d rejected with EINVAL\n",
			       target_node);
			return 0;
		}
		err(1, "KVM_CREATE_GUEST_MEMFD(bind node %d)", target_node);
	}
	if (!node_has_memory(target_node))
		errx(1, "FAIL: memoryless node %d should have been rejected",
		     target_node);
	printf("OK: created gmem fd=%d bound to node %d\n", gmem, target_node);

	mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, gmem, 0);
	if (mem == MAP_FAILED)
		err(1, "mmap gmem");

	/* Fault every page in (no mbind on this mapping). */
	memset(mem, 0xaa, size);

	for (i = 0; i < size / page_size; i++) {
		long node = move_pages_status(mem + i * page_size);

		printf("page %zu -> node %ld (want %d)\n", i, node, target_node);
		if (node != target_node)
			errx(1, "FAIL: page %zu landed on node %ld, wanted %d",
			     i, node, target_node);
	}

	printf("PASS: all %zu pages on node %d via FLAG_BIND_NODE (no mbind)\n",
	       size / page_size, target_node);

	munmap(mem, size);
	close(gmem);
	close(vm);
	close(kvm);
	return 0;
}
