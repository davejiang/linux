// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for the private-node (anondax) placement selftests.  Driven by the
 * private_node_*.sh KTAP scripts, which own provisioning and the verdicts; this
 * tool only performs an mmap/fault and reports residency, so it prints facts
 * and exits 0 (KSFT_SKIP on a setup error the script should treat as a skip).
 *
 *   private_node_tool map    <daxdev> <MB> <nid>   fault MB, report node residency
 *   private_node_tool shared <daxdev>              probe that MAP_SHARED is rejected
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#define KSFT_SKIP 4

/* Sum, from /proc/self/numa_maps, the pages of the mapping at @addr that live
 * on node @nid, and the total mapped pages.  numa_maps reports "N<nid>=<pages>".
 */
static void numa_residency(unsigned long addr, int nid,
			   unsigned long *total, unsigned long *on_nid)
{
	char line[4096];
	FILE *f = fopen("/proc/self/numa_maps", "r");

	*total = *on_nid = 0;
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		unsigned long start;
		char *tok;

		if (sscanf(line, "%lx", &start) != 1 || start != addr)
			continue;
		for (tok = strtok(line, " \t\n"); tok; tok = strtok(NULL, " \t\n")) {
			int n;
			unsigned long pages;

			if (tok[0] == 'N' && sscanf(tok, "N%d=%lu", &n, &pages) == 2) {
				*total += pages;
				if (n == nid)
					*on_nid += pages;
			}
		}
		break;
	}
	fclose(f);
}

static int do_map(const char *dev, unsigned long mb, int nid)
{
	unsigned long len = mb << 20, total, on_nid;
	int fd = open(dev, O_RDWR);
	void *p;

	if (fd < 0) {
		fprintf(stderr, "open(%s): %m\n", dev);
		return KSFT_SKIP;
	}
	/* anondax rejects VM_SHARED; the mapping becomes ordinary anon memory. */
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "mmap(%s): %m\n", dev);
		close(fd);
		return KSFT_SKIP;
	}
	memset(p, 1, len);			/* fault every page */
	numa_residency((unsigned long)p, nid, &total, &on_nid);
	printf("total_pages=%lu on_node%d=%lu\n", total, nid, on_nid);
	munmap(p, len);
	close(fd);
	return 0;
}

static int do_shared(const char *dev)
{
	int fd = open(dev, O_RDWR);
	void *p;

	if (fd < 0) {
		fprintf(stderr, "open(%s): %m\n", dev);
		return KSFT_SKIP;
	}
	p = mmap(NULL, 2UL << 20, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	printf("shared_mmap=%s errno=%d\n",
	       p == MAP_FAILED ? "rejected" : "accepted",
	       p == MAP_FAILED ? errno : 0);
	if (p != MAP_FAILED)
		munmap(p, 2UL << 20);
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 5 && !strcmp(argv[1], "map"))
		return do_map(argv[2], strtoul(argv[3], NULL, 0), atoi(argv[4]));
	if (argc >= 3 && !strcmp(argv[1], "shared"))
		return do_shared(argv[2]);
	fprintf(stderr, "usage: %s map <daxdev> <MB> <nid> | shared <daxdev>\n", argv[0]);
	return KSFT_SKIP;
}
