// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for the private-node (anondax) selftests.  Driven by the
 * private_node_*.sh KTAP scripts, which own provisioning and the verdicts; this
 * tool performs an mmap/fault/policy operation and reports facts, exiting 0
 * (KSFT_SKIP on a setup error the script should treat as a skip).  A few verbs
 * (daxswap, daxcpuset) fold a self-contained pass/fail into the exit status
 * because the verdict needs in-process signal/counter state; the script maps the
 * exit code to a KTAP result.
 *
 *   map      <daxdev> <MB> <nid>             fault MB, report node residency
 *   shared   <daxdev>                        probe that MAP_SHARED is rejected
 *   ltpin    <daxdev> <MB> <nid>             FOLL_LONGTERM pin, report result
 *   anon     <MB> [hold_s]                   anon alloc, hold (for numa_maps reads)
 *   churn    <MB> [secs]                     paced anon pressure to drive reclaim/OOM
 *   daxmap   <daxdev> <MB> <nid> [hold_s]    fault a dax mapping, report+hold
 *   daxmadv  <daxdev> <MB> <pageout|cold|free>  fault then madvise
 *   daxswap  <daxdev> <nid> <MB> [evict_MB]  swap round-trip (rc 0 pass/1 fail/2 skip)
 *   daxcpuset <daxdev> <MB> [pnid]           fault, drop cpuset, refault (rc 0 spilled off pnid)
 *   mbind    <nid> <MB>                      mbind(MPOL_BIND|STATIC) anon, report
 *   mbindns  <nid> <MB>                      mbind without STATIC_NODES
 *   mbindthp <nid> <MB> [hold_s]             mbind a THP range, hold
 *   mbindmask <MB> <nid>...                  mbind(MPOL_BIND) to a node mask
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include "../../../../mm/gup_test.h"

#define KSFT_SKIP 4
#define GUP_TEST_FILE "/sys/kernel/debug/gup_test"
#define MAXNODE 256

#ifndef MPOL_DEFAULT
#define MPOL_DEFAULT 0
#endif
#ifndef MPOL_BIND
#define MPOL_BIND 2
#endif
#ifndef MPOL_MF_STRICT
#define MPOL_MF_STRICT	(1 << 0)
#define MPOL_MF_MOVE	(1 << 1)
#endif
#ifndef MPOL_F_STATIC_NODES
#define MPOL_F_STATIC_NODES (1 << 15)
#endif
#ifndef MADV_COLD
#define MADV_COLD	20
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT	21
#endif
#ifndef MADV_FREE
#define MADV_FREE	8
#endif
#define HP_SIZE		(2UL << 20)
#define DAXSWAP_MAGIC	0x5741504bUL	/* "SWAP" */

static long sys_mbind(void *addr, unsigned long len, int mode,
		      const unsigned long *nmask, unsigned long maxnode, unsigned int flags)
{
	return syscall(__NR_mbind, addr, len, mode, nmask, maxnode, flags);
}
static long sys_move_pages(int pid, unsigned long count, void **pages,
			   const int *nodes, int *status, int flags)
{
	return syscall(__NR_move_pages, pid, count, pages, nodes, status, flags);
}
static long sys_set_mempolicy(int mode, const unsigned long *nmask,
			      unsigned long maxnode)
{
	return syscall(__NR_set_mempolicy, mode, nmask, maxnode);
}
static long sys_set_mempolicy_home_node(unsigned long start, unsigned long len,
					unsigned long home_node, unsigned long flags)
{
	return syscall(__NR_set_mempolicy_home_node, start, len, home_node, flags);
}

static void set_bit_node(unsigned long *mask, int nid)
{
	memset(mask, 0, MAXNODE / 8);
	mask[nid / (8 * sizeof(long))] |= 1UL << (nid % (8 * sizeof(long)));
}

/* Node the page at @addr resides on, or <0 on error. */
static int page_node(void *addr)
{
	void *p = addr;
	int status = -1;

	if (sys_move_pages(0, 1, &p, NULL, &status, 0) != 0)
		return -errno;
	return status;
}

/* Read a named counter from /proc/vmstat (e.g. "pswpin"); -1 if not found. */
static long vmstat(const char *name)
{
	char line[256];
	long val = -1;
	size_t nl = strlen(name);
	FILE *f = fopen("/proc/vmstat", "r");

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f))
		if (!strncmp(line, name, nl) && line[nl] == ' ') {
			val = atol(line + nl + 1);
			break;
		}
	fclose(f);
	return val;
}

/* Sum, from /proc/self/numa_maps, the pages of the mapping at @addr that live
 * on node @nid, the total mapped pages, and the swapped-out pages.
 */
static void numa_residency(unsigned long addr, int nid, unsigned long *total,
			   unsigned long *on_nid, unsigned long *swap)
{
	char line[8192];
	FILE *f = fopen("/proc/self/numa_maps", "r");

	*total = *on_nid = 0;
	if (swap)
		*swap = 0;
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

			if (swap && !strncmp(tok, "swap=", 5))
				*swap = atol(tok + 5);
			else if (tok[0] == 'N' && sscanf(tok, "N%d=%lu", &n, &pages) == 2) {
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
	numa_residency((unsigned long)p, nid, &total, &on_nid, NULL);
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
	numa_residency((unsigned long)p, nid, &total, &on_nid, NULL);
	printf("pinned=%s total_pages=%lu on_node%d=%lu\n",
	       pinned ? "yes" : "no", total, nid, on_nid);
	if (pinned)
		ioctl(gup, PIN_LONGTERM_TEST_STOP);
	munmap(p, len);
	close(fd);
	close(gup);
	return 0;
}

static int do_anon(long mb, long hold_s)
{
	size_t len = (size_t)mb << 20;
	char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

	if (p == MAP_FAILED) {
		printf("anon: mmap(%ld MB) FAILED: %m\n", mb);
		return 1;
	}
	memset(p, 1, len);
	printf("anon: populated %ld MB (first page node=%d)\n", mb, page_node(p));
	fflush(stdout);
	sleep(hold_s);
	return 0;
}

/*
 * Paced pressure: mmap anon WITHOUT MAP_POPULATE and repeatedly walk it,
 * faulting pages gradually so kswapd can page out the working-set overflow to
 * swap instead of a MAP_POPULATE burst tripping the OOM killer.  Sizing @mb
 * above available DRAM forces sustained reclaim.
 */
static int do_churn(long mb, long secs)
{
	size_t len = (size_t)mb << 20;
	long ps = sysconf(_SC_PAGESIZE);
	size_t np = len / ps, i;
	time_t end;
	char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED) {
		printf("churn: mmap(%ld MB) FAILED: %m\n", mb);
		return 1;
	}
	printf("churn: %ld MB, %ld s, walking gradually to drive reclaim\n", mb, secs);
	fflush(stdout);
	end = time(NULL) + secs;
	do {
		for (i = 0; i < np; i++)
			*(volatile char *)(p + i * ps) = (char)i;
	} while (time(NULL) < end);
	return 0;
}

static int do_daxmap(const char *path, long mb, int nid, long hold)
{
	size_t len = (size_t)mb << 20;
	unsigned long total, on_nid;
	long ps = sysconf(_SC_PAGESIZE);
	int fd = open(path, O_RDWR);
	char *p;

	if (fd < 0) {
		fprintf(stderr, "daxmap: open(%s): %m\n", path);
		return KSFT_SKIP;
	}
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "daxmap: mmap(%ld MB): %m\n", mb);
		close(fd);
		return KSFT_SKIP;
	}
	for (size_t i = 0; i < len; i += ps)
		*(volatile char *)(p + i) = 1;
	numa_residency((unsigned long)p, nid, &total, &on_nid, NULL);
	printf("daxmap: total_pages=%lu on_node%d=%lu (first=%d)\n",
	       total, nid, on_nid, page_node(p));
	fflush(stdout);
	sleep(hold);
	munmap(p, len);
	close(fd);
	return 0;
}

static sigjmp_buf sigbus_jb;
static void on_sigbus(int sig) { siglongjmp(sigbus_jb, 1); }

/*
 * SIGBUS-tolerant walk of a dax mapping: fault @mb repeatedly for @secs, and on
 * a node-full SIGBUS restart the walk.  Sustains pressure on the private node so
 * its reclaim/demotion path drains it (used to drive demotion *out* of a private
 * node that sits above DRAM in the tier order).
 */
static int do_daxchurn(const char *path, long mb, long secs)
{
	size_t len = (size_t)mb << 20, i;
	long ps = sysconf(_SC_PAGESIZE);
	struct sigaction sa = { .sa_handler = on_sigbus }, old;
	time_t end;
	int fd = open(path, O_RDWR);
	char *p;

	if (fd < 0) {
		fprintf(stderr, "daxchurn: open(%s): %m\n", path);
		return KSFT_SKIP;
	}
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		fprintf(stderr, "daxchurn: mmap(%ld MB): %m\n", mb);
		return KSFT_SKIP;
	}
	printf("daxchurn: %ld MB, %ld s, SIGBUS-tolerant walk to drive demotion\n", mb, secs);
	fflush(stdout);
	sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, &old);
	end = time(NULL) + secs;
	do {
		if (sigsetjmp(sigbus_jb, 1) == 0)
			for (i = 0; i < len; i += ps)
				*(volatile char *)(p + i) = 1;
		/* a SIGBUS lands here; the outer loop restarts so demotion drains */
	} while (time(NULL) < end);
	sigaction(SIGBUS, &old, NULL);
	munmap(p, len);
	return 0;
}

/* Fault a dax mapping, then madvise() it (pageout|cold|free). */
static int do_daxmadv(const char *path, long mb, const char *adv)
{
	size_t len = (size_t)mb << 20;
	long ps = sysconf(_SC_PAGESIZE);
	int advice, rc, fd = open(path, O_RDWR);
	char *p;

	if (!strcmp(adv, "pageout"))
		advice = MADV_PAGEOUT;
	else if (!strcmp(adv, "cold"))
		advice = MADV_COLD;
	else if (!strcmp(adv, "free"))
		advice = MADV_FREE;
	else {
		fprintf(stderr, "daxmadv: unknown advice '%s'\n", adv);
		return KSFT_SKIP;
	}
	if (fd < 0) {
		fprintf(stderr, "daxmadv: open(%s): %m\n", path);
		return KSFT_SKIP;
	}
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "daxmadv: mmap(%ld MB): %m\n", mb);
		return KSFT_SKIP;
	}
	for (size_t i = 0; i < len; i += ps)
		*(volatile char *)(p + i) = 1;
	printf("daxmadv: faulted %ld MB on node=%d\n", mb, page_node(p));
	errno = 0;
	rc = madvise(p, len, advice);
	printf("daxmadv: madvise(%s) rc=%d errno=%d (%s)\n",
	       adv, rc, errno, rc ? strerror(errno) : "ok");
	fflush(stdout);
	sleep(3);
	return 0;
}

/*
 * Pressure the private node by faulting an anondax mapping of @path until the
 * node is full (SIGBUS) or @cap_mb is reached, then unmap it.  Drops clean
 * swap-cache folios off the node so a later read of a paged-out region really
 * swaps in.  Returns MB actually faulted.
 */
static long daxswap_evict_cache(const char *path, long cap_mb)
{
	long ps = sysconf(_SC_PAGESIZE);
	size_t len = (size_t)cap_mb << 20, done = 0;
	struct sigaction sa = { .sa_handler = on_sigbus }, old;
	int fd = open(path, O_RDWR);
	char *b;

	if (fd < 0)
		return 0;
	b = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (b == MAP_FAILED)
		return 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, &old);
	if (sigsetjmp(sigbus_jb, 1) == 0)
		for (done = 0; done < len; done += ps)
			*(volatile char *)(b + done) = 1;
	sigaction(SIGBUS, &old, NULL);
	munmap(b, len);
	return (long)(done >> 20);
}

/*
 * Swap round-trip for an anondax mapping.  Fault <MB> onto the private node,
 * stamp a per-page signature, page it out with MADV_PAGEOUT, evict the clean
 * swap-cache copies off the node, then read every page back -- which must really
 * swap in.  PASS (rc 0) requires: pswpin increased, the signature survived, and
 * the reallocated folios landed back on the private node.  rc 2 == inconclusive
 * (no swap-in happened / data lost: raise evict_mb) -> the script SKIPs.
 */
static int do_daxswap(const char *path, int nid, long mb, long evict_mb)
{
	long ps = sysconf(_SC_PAGESIZE);
	size_t len = (size_t)mb << 20, i;
	unsigned long resident, back, dummy;
	long bad = 0, zero = 0, swpin0, swpin1, ev;
	int rc, fd = open(path, O_RDWR);
	char *p;

	if (fd < 0) {
		fprintf(stderr, "daxswap: open(%s): %m\n", path);
		return KSFT_SKIP;
	}
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "daxswap: mmap(%ld MB): %m\n", mb);
		return KSFT_SKIP;
	}
	for (i = 0; i < len; i += ps)
		*(volatile unsigned long *)(p + i) = (i / ps) ^ DAXSWAP_MAGIC;
	numa_residency((unsigned long)p, nid, &dummy, &resident, NULL);
	if (resident == 0) {
		printf("daxswap: nothing landed on node%d\n", nid);
		return 1;
	}
	errno = 0;
	rc = madvise(p, len, MADV_PAGEOUT);
	printf("daxswap: madvise(PAGEOUT) rc=%d (%s)\n", rc, rc ? strerror(errno) : "ok");
	fflush(stdout);
	sleep(2);
	ev = daxswap_evict_cache(path, evict_mb);
	printf("daxswap: pressured node%d with %ld MB to drop swap cache\n", nid, ev);
	sleep(1);

	swpin0 = vmstat("pswpin");
	for (i = 0; i < len; i += ps) {
		unsigned long got = *(volatile unsigned long *)(p + i);

		if (got != ((i / ps) ^ DAXSWAP_MAGIC)) {
			bad++;
			if (got == 0)
				zero++;
		}
	}
	swpin1 = vmstat("pswpin");
	numa_residency((unsigned long)p, nid, &dummy, &back, NULL);
	printf("daxswap: %ld/%ld pages intact (%ld corrupt, %ld zeroed); pswpin +%ld; back_on_node%d=%lu/%lu\n",
	       (long)(len / ps) - bad, (long)(len / ps), bad, zero,
	       swpin1 - swpin0, nid, back, resident);
	fflush(stdout);

	if (swpin1 - swpin0 <= 0 || bad)
		return 2;			/* inconclusive -> script SKIPs */
	return back >= resident ? 0 : 1;
}

/*
 * cpuset-rebind probe.  Fault a page (phase 1, node still in cpuset), sleep so
 * the caller can drop the private node from cpuset.mems, then fault a FRESH page
 * (phase 2).  A private bind is not strict against the cpuset: once the node
 * leaves cpuset.mems the bind is unsatisfiable, so the fault falls back to the
 * cpuset-allowed memory (DRAM) rather than killing the task -- "ask for a node
 * the cpuset forbids, get whatever the cpuset does allow."  Pass @pnid to verify
 * phase 2 lands OFF the private node.
 *   rc 0 == phase 2 spilled off the private node (PASS)
 *   rc 1 == phase 2 landed on the private node (FAIL: bind not actually dropped)
 *   rc 2 == phase 2 took SIGBUS (FAIL: no fallback)
 */
static int do_daxcpuset(const char *path, long mb, int pnid)
{
	size_t len = (size_t)mb << 20;
	struct sigaction sa = { .sa_handler = on_sigbus }, old;
	int fd = open(path, O_RDWR);
	char *p;
	int n1, n2;

	if (fd < 0) {
		fprintf(stderr, "daxcpuset: open(%s): %m\n", path);
		return KSFT_SKIP;
	}
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		fprintf(stderr, "daxcpuset: mmap(%ld MB): %m\n", mb);
		return KSFT_SKIP;
	}
	*(volatile char *)p = 1;
	n1 = page_node(p);
	printf("daxcpuset: phase1 faulted ok on node%d, pid=%d; sleeping for cpuset drop\n",
	       n1, getpid());
	fflush(stdout);
	sleep(5);

	sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, &old);
	if (sigsetjmp(sigbus_jb, 1) == 0) {
		*(volatile char *)(p + len / 2) = 1;
		sigaction(SIGBUS, &old, NULL);
		n2 = page_node(p + len / 2);
		printf("daxcpuset: phase2 fault spilled to node%d (private node%d dropped from cpuset)\n",
		       n2, pnid);
		return (pnid >= 0 && n2 == pnid) ? 1 : 0;
	}
	sigaction(SIGBUS, &old, NULL);
	printf("daxcpuset: phase2 fault took SIGBUS\n");
	return 2;
}

/* mbind a FRESH anon range onto @nid, fault it, report landing, hold @hold s. */
static int do_mbind_flags(int nid, long mb, long hold, int mode_flags, const char *tag)
{
	unsigned long mask[MAXNODE / (8 * sizeof(long))], total, on_nid;
	long ps = sysconf(_SC_PAGESIZE), npg = ((long)mb << 20) / ps, rc;
	size_t len = (size_t)mb << 20;
	char *p;

	set_bit_node(mask, nid);
	p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "%s: mmap: %m\n", tag);
		return KSFT_SKIP;
	}
	errno = 0;
	rc = sys_mbind(p, len, MPOL_BIND | mode_flags, mask, MAXNODE, 0);
	printf("%s: mbind(MPOL_BIND%s, node %d) rc=%ld errno=%d (%s)\n",
	       tag, (mode_flags & MPOL_F_STATIC_NODES) ? "|STATIC" : "", nid, rc,
	       errno, rc ? strerror(errno) : "ok");
	if (rc) {
		munmap(p, len);
		return 0;			/* rejected: script decides if expected */
	}
	for (long i = 0; i < npg; i++)
		p[i * ps] = 1;
	numa_residency((unsigned long)p, nid, &total, &on_nid, NULL);
	printf("%s: faulted %ld pages -> on_node%d=%lu total=%lu\n",
	       tag, npg, nid, on_nid, total);
	fflush(stdout);
	if (hold)
		sleep(hold);		/* keep resident so the script can read stats */
	munmap(p, len);
	return 0;
}

/* mbind a 2MB-aligned, MADV_HUGEPAGE anon range onto @nid (PMD THPs), hold. */
static int do_mbindthp(int nid, long mb, long hold)
{
	unsigned long mask[MAXNODE / (8 * sizeof(long))], total, on_nid;
	size_t len = (size_t)mb << 20;
	long rc, touched = 0;
	char *base, *p;

	set_bit_node(mask, nid);
	base = mmap(NULL, len + HP_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) {
		fprintf(stderr, "mbindthp: mmap: %m\n");
		return KSFT_SKIP;
	}
	p = (char *)(((unsigned long)base + HP_SIZE - 1) & ~(HP_SIZE - 1));
	if (madvise(p, len, MADV_HUGEPAGE))
		fprintf(stderr, "mbindthp: madvise(HUGEPAGE): %m\n");
	errno = 0;
	rc = sys_mbind(p, len, MPOL_BIND | MPOL_F_STATIC_NODES, mask, MAXNODE, 0);
	printf("mbindthp: mbind(node %d) rc=%ld errno=%d (%s)\n",
	       nid, rc, errno, rc ? strerror(errno) : "ok");
	if (rc)
		return 0;
	for (size_t off = 0; off < len; off += HP_SIZE) {
		p[off] = 1;
		touched += HP_SIZE / 4096;
	}
	numa_residency((unsigned long)p, nid, &total, &on_nid, NULL);
	printf("mbindthp: faulted %zu MB -> on_node%d=%lu total=%lu (off=%lu)\n",
	       len >> 20, nid, on_nid, total, total - on_nid);
	fflush(stdout);
	sleep(hold);
	return 0;
}

/* mbind(MPOL_BIND) a fresh anon range to a multi-node mask, fault, report. */
static int do_mbindmask(long mb, int nnids, char **nidv)
{
	unsigned long mask[MAXNODE / (8 * sizeof(long))], total, on_nid;
	long ps = sysconf(_SC_PAGESIZE), npg = ((long)mb << 20) / ps, rc;
	size_t len = (size_t)mb << 20;
	char list[128] = "";
	int i, nid0 = atoi(nidv[0]);
	char *p;

	p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "mbindmask: mmap: %m\n");
		return KSFT_SKIP;
	}
	memset(mask, 0, MAXNODE / 8);
	for (i = 0; i < nnids; i++) {
		int nid = atoi(nidv[i]);

		mask[nid / (8 * sizeof(long))] |= 1UL << (nid % (8 * sizeof(long)));
		snprintf(list + strlen(list), sizeof(list) - strlen(list),
			 "%s%d", i ? "," : "", nid);
	}
	errno = 0;
	rc = sys_mbind(p, len, MPOL_BIND, mask, MAXNODE, 0);
	printf("mbindmask: nodes={%s} rc=%ld errno=%d (%s)\n",
	       list, rc, errno, rc ? strerror(errno) : "ok");
	if (!rc) {
		for (long j = 0; j < npg; j++)
			p[j * ps] = 1;
		numa_residency((unsigned long)p, nid0, &total, &on_nid, NULL);
		printf("mbindmask: faulted %ld pages -> on_node%d=%lu total=%lu\n",
		       npg, nid0, on_nid, total);
	}
	munmap(p, len);
	return 0;
}

/*
 * Probe whether set_mempolicy(MPOL_BIND, {nid}) is honored for a private node
 * (CAP_MEMPOLICY) -- report the rc only and immediately reset to the default
 * policy.  We deliberately do NOT fault under it: a *process-wide* strict bind
 * to a ZONE_MOVABLE private node would force even unmovable allocations (page
 * tables) onto a movable zone with no fallback and wedge the process.  Per-VMA
 * placement is exercised by the mbind test; here we only validate the gate.
 */
static int do_setmempol(int nid, long mb)
{
	unsigned long mask[MAXNODE / (8 * sizeof(long))];
	long rc;

	(void)mb;
	set_bit_node(mask, nid);
	errno = 0;
	rc = sys_set_mempolicy(MPOL_BIND, mask, MAXNODE);
	printf("setmempol: set_mempolicy(MPOL_BIND, node %d) rc=%ld errno=%d (%s)\n",
	       nid, rc, errno, rc ? strerror(errno) : "ok");
	if (!rc)
		sys_set_mempolicy(MPOL_DEFAULT, NULL, 0);	/* don't taint the process */
	return 0;
}

/*
 * Deliberately wedge-prone probe: process-wide set_mempolicy(MPOL_BIND, {nid})
 * then fault anon.  If @nid is movable-only, even the fault's page-table
 * allocations are forced onto a movable zone with no fallback.  Prints
 * "bindfault: done" only if it completes; the caller watchdogs for a wedge.
 */
static int do_bindfault(int nid, long mb)
{
	unsigned long mask[MAXNODE / (8 * sizeof(long))], total, on_nid;
	long ps = sysconf(_SC_PAGESIZE), npg = ((long)mb << 20) / ps;
	size_t len = (size_t)mb << 20;
	char *p;

	set_bit_node(mask, nid);
	if (sys_set_mempolicy(MPOL_BIND, mask, MAXNODE)) {
		printf("bindfault: set_mempolicy(node %d) rc=-1 errno=%d (%s)\n",
		       nid, errno, strerror(errno));
		return 0;
	}
	printf("bindfault: bound MPOL_BIND {%d}, faulting %ld MB...\n", nid, mb);
	fflush(stdout);
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		printf("bindfault: mmap: %m\n");
		return 0;
	}
	for (long i = 0; i < npg; i++)
		p[i * ps] = 1;			/* may wedge here on a movable-only bind */
	numa_residency((unsigned long)p, nid, &total, &on_nid, NULL);
	sys_set_mempolicy(MPOL_DEFAULT, NULL, 0);
	printf("bindfault: done -> on_node%d=%lu total=%lu\n", nid, on_nid, total);
	munmap(p, len);
	return 0;
}

/*
 * mbind a range to a base (real) node, then set its home node.  home_node is
 * only a preferred-nid hint -- placement stays governed by the bind nodemask
 * ({base} here) -- so even a private home node must not be CAP-gated and must
 * not pull the allocation onto itself.  Report rc, and on success fault and
 * report how many pages landed on the home node (expected 0 when home != base).
 */
static int do_sethome(int home_nid, int base_nid, long mb)
{
	unsigned long mask[MAXNODE / (8 * sizeof(long))], total, on_home;
	long ps = sysconf(_SC_PAGESIZE), npg = ((long)mb << 20) / ps;
	size_t len = (size_t)mb << 20;
	long rc;
	char *p;

	p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "sethome: mmap: %m\n");
		return KSFT_SKIP;
	}
	set_bit_node(mask, base_nid);
	if (sys_mbind(p, len, MPOL_BIND | MPOL_F_STATIC_NODES, mask, MAXNODE, 0)) {
		fprintf(stderr, "sethome: base mbind(node %d): %m\n", base_nid);
		munmap(p, len);
		return KSFT_SKIP;
	}
	errno = 0;
	rc = sys_set_mempolicy_home_node((unsigned long)p, len, home_nid, 0);
	if (rc) {
		printf("sethome: set_mempolicy_home_node(home %d, base %d) rc=%ld errno=%d (%s)\n",
		       home_nid, base_nid, rc, errno, strerror(errno));
		munmap(p, len);
		return 0;
	}
	for (long i = 0; i < npg; i++)
		p[i * ps] = 1;
	numa_residency((unsigned long)p, home_nid, &total, &on_home, NULL);
	printf("sethome: set_mempolicy_home_node(home %d, base %d) rc=0 ok; faulted %lu pages -> on_home%d=%lu\n",
	       home_nid, base_nid, total, home_nid, on_home);
	munmap(p, len);
	return 0;
}

/*
 * move_pages() a single private-node folio (faulted from @path) toward @target.
 * Reports the resulting per-page status: a private folio is migratable only if
 * its node allows mempolicy placement (CAP_MEMPOLICY) -- otherwise -ENOENT.
 */
static int do_movepages(const char *path, int target_nid)
{
	long ps = sysconf(_SC_PAGESIZE);
	int fd = open(path, O_RDWR);
	void *pages[1];
	int nodes[1] = { target_nid };
	int status[1] = { 0x7fffffff };
	char *p;

	if (fd < 0) {
		fprintf(stderr, "movepages: open(%s): %m\n", path);
		return KSFT_SKIP;
	}
	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		fprintf(stderr, "movepages: mmap: %m\n");
		return KSFT_SKIP;
	}
	*(volatile char *)p = 1;			/* fault onto the private node */
	pages[0] = p;
	errno = 0;
	if (sys_move_pages(0, 1, pages, nodes, status, MPOL_MF_MOVE) != 0) {
		printf("movepages: src node%d -> target %d: move_pages rc=-1 errno=%d (%s)\n",
		       page_node(p), target_nid, errno, strerror(errno));
		munmap(p, ps);
		return 0;
	}
	printf("movepages: src -> target %d: status=%d (%s); now on node%d\n",
	       target_nid, status[0],
	       status[0] < 0 ? strerror(-status[0]) : "moved", page_node(p));
	munmap(p, ps);
	return 0;
}

/*
 * move_pages() a normal (DRAM) anon page TO @target.  A private node is a valid
 * move_pages() target only when it allows mempolicy placement (CAP_MEMPOLICY);
 * otherwise the syscall fails -ENODEV (private nodes are not N_MEMORY).
 */
static int do_movepagesto(int target_nid)
{
	long ps = sysconf(_SC_PAGESIZE);
	void *pages[1];
	int nodes[1] = { target_nid };
	int status[1] = { 0x7fffffff };
	char *p;

	p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "movepagesto: mmap: %m\n");
		return KSFT_SKIP;
	}
	*(volatile char *)p = 1;			/* fault onto a normal node */
	pages[0] = p;
	errno = 0;
	if (sys_move_pages(0, 1, pages, nodes, status, MPOL_MF_MOVE) != 0) {
		printf("movepagesto: -> target %d: move_pages rc=-1 errno=%d (%s)\n",
		       target_nid, errno, strerror(errno));
		munmap(p, ps);
		return 0;
	}
	printf("movepagesto: -> target %d: status=%d (%s); now on node%d\n",
	       target_nid, status[0],
	       status[0] < 0 ? strerror(-status[0]) : "moved", page_node(p));
	munmap(p, ps);
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
	if (argc >= 3 && !strcmp(argv[1], "anon"))
		return do_anon(atol(argv[2]), argc >= 4 ? atol(argv[3]) : 10);
	if (argc >= 3 && !strcmp(argv[1], "churn"))
		return do_churn(atol(argv[2]), argc >= 4 ? atol(argv[3]) : 12);
	if (argc >= 5 && !strcmp(argv[1], "daxmap"))
		return do_daxmap(argv[2], atol(argv[3]), atoi(argv[4]),
				 argc >= 6 ? atol(argv[5]) : 8);
	if (argc >= 4 && !strcmp(argv[1], "daxchurn"))
		return do_daxchurn(argv[2], atol(argv[3]), argc >= 5 ? atol(argv[4]) : 30);
	if (argc == 5 && !strcmp(argv[1], "daxmadv"))
		return do_daxmadv(argv[2], atol(argv[3]), argv[4]);
	if (argc >= 5 && !strcmp(argv[1], "daxswap"))
		return do_daxswap(argv[2], atoi(argv[3]), atol(argv[4]),
				  argc >= 6 ? atol(argv[5]) : 1024);
	if (argc >= 4 && !strcmp(argv[1], "daxcpuset"))
		return do_daxcpuset(argv[2], atol(argv[3]),
				    argc >= 5 ? atoi(argv[4]) : -1);
	if (argc >= 4 && !strcmp(argv[1], "mbind"))
		return do_mbind_flags(atoi(argv[2]), atol(argv[3]),
				      argc >= 5 ? atol(argv[4]) : 0,
				      MPOL_F_STATIC_NODES, "mbind");
	if (argc >= 4 && !strcmp(argv[1], "mbindns"))
		return do_mbind_flags(atoi(argv[2]), atol(argv[3]),
				      argc >= 5 ? atol(argv[4]) : 0, 0, "mbindns");
	if (argc >= 4 && !strcmp(argv[1], "mbindthp"))
		return do_mbindthp(atoi(argv[2]), atol(argv[3]),
				   argc >= 5 ? atol(argv[4]) : 0);
	if (argc >= 4 && !strcmp(argv[1], "mbindmask"))
		return do_mbindmask(atol(argv[2]), argc - 3, &argv[3]);
	if (argc == 4 && !strcmp(argv[1], "setmempol"))
		return do_setmempol(atoi(argv[2]), atol(argv[3]));
	if (argc == 5 && !strcmp(argv[1], "sethome"))
		return do_sethome(atoi(argv[2]), atoi(argv[3]), atol(argv[4]));
	if (argc == 4 && !strcmp(argv[1], "bindfault"))
		return do_bindfault(atoi(argv[2]), atol(argv[3]));
	if (argc == 4 && !strcmp(argv[1], "movepages"))
		return do_movepages(argv[2], atoi(argv[3]));
	if (argc == 3 && !strcmp(argv[1], "movepagesto"))
		return do_movepagesto(atoi(argv[2]));

	fprintf(stderr,
		"usage: %s map <daxdev> <MB> <nid> | shared <daxdev> | ltpin <daxdev> <MB> <nid> |\n"
		"       anon <MB> [hold] | churn <MB> [secs] | daxmap <daxdev> <MB> <nid> [hold] |\n"
		"       daxchurn <daxdev> <MB> [secs] | daxmadv <daxdev> <MB> <pageout|cold|free> |\n"
		"       daxswap <daxdev> <nid> <MB> [evict_MB] |\n"
		"       daxcpuset <daxdev> <MB> [pnid] | mbind <nid> <MB> [hold] | mbindns <nid> <MB> [hold] |\n"
		"       mbindthp <nid> <MB> [hold] | mbindmask <MB> <nid>... |\n"
		"       setmempol <nid> <MB> | sethome <home_nid> <base_nid> <MB> |\n"
		"       movepages <daxdev> <target_nid> | movepagesto <target_nid>\n",
		argv[0]);
	return KSFT_SKIP;
}
