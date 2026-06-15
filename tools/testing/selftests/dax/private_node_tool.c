// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for the private-node (anondax) placement selftests.  Driven by the
 * private_node_*.sh KTAP scripts, which own provisioning and the verdicts; this
 * tool only performs an mmap/fault and reports residency, so it prints facts
 * and exits 0 (KSFT_SKIP on a setup error the script should treat as a skip).
 *
 *   private_node_tool map    <daxdev> <MB> <nid>   fault MB, report node residency
 *   private_node_tool shared <daxdev>              probe that MAP_SHARED is rejected
 *   private_node_tool ltpin  <daxdev> <MB> <nid>   FOLL_LONGTERM pin, report result
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "../../../../mm/gup_test.h"

#define KSFT_SKIP 4
#define GUP_TEST_FILE "/sys/kernel/debug/gup_test"

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

/* Attempt a FOLL_PIN|FOLL_LONGTERM pin of an anondax mapping and report whether
 * it succeeded and where the folios ended up.  A private-node folio that did not
 * opt into NODE_PRIVATE_CAP_LTPIN must fail the pin AND stay in place (it is
 * neither pinnable nor migratable); an opted-in node pins like ordinary memory.
 */
static int do_ltpin(const char *dev, unsigned long mb, int nid)
{
	unsigned long len = mb << 20, total, on_nid;
	struct pin_longterm_test t = { 0 };
	int fd, gup, pinned;
	void *p;

	gup = open(GUP_TEST_FILE, O_RDWR);
	if (gup < 0) {
		fprintf(stderr, "open(%s): %m (need CONFIG_GUP_TEST + debugfs)\n", GUP_TEST_FILE);
		return KSFT_SKIP;
	}
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %m\n", dev);
		return KSFT_SKIP;
	}
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "mmap(%s): %m\n", dev);
		return KSFT_SKIP;
	}
	memset(p, 1, len);

	t.addr = (unsigned long)p;
	t.size = len;
	t.flags = 0;				/* slow-path read FOLL_LONGTERM pin */
	pinned = ioctl(gup, PIN_LONGTERM_TEST_START, &t) == 0;
	numa_residency((unsigned long)p, nid, &total, &on_nid);
	printf("pinned=%s total_pages=%lu on_node%d=%lu\n",
	       pinned ? "yes" : "no", total, nid, on_nid);
	if (pinned)
		ioctl(gup, PIN_LONGTERM_TEST_STOP);
	munmap(p, len);
	close(fd);
	close(gup);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 5 && !strcmp(argv[1], "map"))
		return do_map(argv[2], strtoul(argv[3], NULL, 0), atoi(argv[4]));
	if (argc >= 3 && !strcmp(argv[1], "shared"))
		return do_shared(argv[2]);
	if (argc >= 5 && !strcmp(argv[1], "ltpin"))
		return do_ltpin(argv[2], strtoul(argv[3], NULL, 0), atoi(argv[4]));
	fprintf(stderr, "usage: %s map <daxdev> <MB> <nid> | shared <daxdev> | ltpin <daxdev> <MB> <nid>\n",
		argv[0]);
	return KSFT_SKIP;
}
