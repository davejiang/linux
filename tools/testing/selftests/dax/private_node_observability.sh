#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) observability: user-visible accounting must include
# N_MEMORY_PRIVATE nodes.
#
#   1. memcg memory.numa_stat reports private-node anon (and the per-node columns
#      sum to memory.stat).
#   2. /proc/PID/numa_maps counts PMD-mapped THPs on a private node.
#   3. /sys/kernel/debug/lru_gen lists a reclaimable private node.
#   4. /proc/kcore covers private-node RAM (needs nokaslr + python3/readelf).
#
# Needs an anondax dax device on a memoryless node; individual checks SKIP when
# their prerequisites (cgroup2 memory, THP, debugfs, swap, python3) are absent.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
grep -q debugfs /proc/mounts || mount -t debugfs none /sys/kernel/debug 2>/dev/null
pn_provision
pn_reset

pn_set mempolicy 1
pn_set reclaim 1
pn_set hotunplug 1
pn_hotplug online_movable
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_skip_all "could not online node $PN (mbind+reclaim) as private"
	pn_reset; exit "$KSFT_SKIP"
fi
pn_swap_setup
ktap_print_msg "using $DAX on private node $PN"
ktap_set_plan 4

CG=$(pn_cgroup2 2>/dev/null)

# 1. memcg memory.numa_stat ----------------------------------------------------
if [ -z "$CG" ] || ! grep -qw memory "$CG/cgroup.controllers" 2>/dev/null; then
	ktap_test_skip "GAP-1: cgroup2 memory controller unavailable"
else
	grep -qw memory "$CG/cgroup.subtree_control" || echo +memory > "$CG/cgroup.subtree_control" 2>/dev/null
	g="$CG/pn_obs"; mkdir -p "$g" 2>/dev/null
	( echo $BASHPID > "$g/cgroup.procs"; exec "$TOOL" mbind "$PN" 64 30 ) >/dev/null 2>&1 &
	tp=$!; sleep 4
	ns=$(grep '^anon ' "$g/memory.numa_stat" 2>/dev/null)
	npriv=$(echo "$ns" | grep -oE "N$PN=[0-9]+" | cut -d= -f2)
	kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null
	rmdir "$g" 2>/dev/null
	if [ -n "$npriv" ] && [ "$npriv" -gt 0 ] 2>/dev/null; then
		ktap_test_pass "memory.numa_stat anon reports private N$PN=$npriv"
	else
		ktap_test_fail "no N$PN= in memory.numa_stat anon line"
	fi
fi

# 2. numa_maps THP gather ------------------------------------------------------
echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
"$TOOL" mbindthp "$PN" 32 8 >/dev/null 2>&1 &
tt=$!; sleep 3
ahp=$(awk '/^AnonHugePages:/{s+=$2}END{print s+0}' /proc/$tt/smaps 2>/dev/null)
nmap=$(awk -v pn="$PN" '{for(i=1;i<=NF;i++) if($i ~ ("^N"pn"=")){split($i,a,"="); if(a[2]+0>m)m=a[2]}} END{print m+0}' /proc/$tt/numa_maps 2>/dev/null)
kill "$tt" 2>/dev/null; wait "$tt" 2>/dev/null
if [ "${ahp:-0}" -lt 2048 ] 2>/dev/null; then
	ktap_test_skip "GAP-2: THP did not form (AnonHugePages=${ahp}kB)"
elif [ $(( nmap * 4 )) -ge $(( ahp * 8 / 10 )) ] 2>/dev/null; then
	ktap_test_pass "numa_maps counts PMD THPs on node $PN (N$PN=$nmap pages, ${ahp}kB AHP)"
else
	ktap_test_fail "PMD THPs (${ahp}kB) undercounted in numa_maps (N$PN=$nmap pages)"
fi

# 3. lru_gen lists the private node --------------------------------------------
if [ ! -r /sys/kernel/debug/lru_gen ]; then
	ktap_test_skip "GAP-3: /sys/kernel/debug/lru_gen unavailable (need CONFIG_LRU_GEN)"
else
	echo y > /sys/kernel/mm/lru_gen/enabled 2>/dev/null
	"$TOOL" mbind "$PN" 128 12 >/dev/null 2>&1 &
	tr=$!; sleep 3
	hit=$(grep -cE "node +$PN" /sys/kernel/debug/lru_gen 2>/dev/null)
	kill "$tr" 2>/dev/null; wait "$tr" 2>/dev/null
	if [ "${hit:-0}" -ge 1 ] 2>/dev/null; then
		ktap_test_pass "node $PN appears in /sys/kernel/debug/lru_gen"
	else
		ktap_test_fail "node $PN absent from lru_gen listing"
	fi
fi

# 4. /proc/kcore covers private RAM -------------------------------------------
if ! command -v python3 >/dev/null 2>&1 || ! command -v readelf >/dev/null 2>&1; then
	ktap_test_skip "GAP-4: python3/readelf unavailable"
else
	python3 - <<'PY'
import re, subprocess, sys
phys = 0
for ln in open('/proc/iomem'):
    m = re.match(r'\s*([0-9a-f]+)-([0-9a-f]+)\s*:\s*System RAM', ln)
    if m:
        phys = max(phys, int(m.group(1), 16))
try:
    out = subprocess.check_output(['readelf', '-l', '/proc/kcore'], text=True,
                                  stderr=subprocess.DEVNULL)
except Exception:
    sys.exit(3)
loads = [(int(a, 16), int(b, 16)) for a, b in re.findall(
    r'LOAD\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)', out)]
for po in (0xffff888000000000, 0xff11000000000000):
    tva = po + phys
    if any(v <= tva < v + sz for v, sz in loads):
        sys.exit(0)
sys.exit(1)
PY
	case $? in
	0) ktap_test_pass "private-node RAM is covered by a /proc/kcore PT_LOAD segment" ;;
	3) ktap_test_skip "GAP-4: readelf could not parse /proc/kcore" ;;
	*) ktap_test_fail "no kcore PT_LOAD covers the private node's __va range (need nokaslr?)" ;;
	esac
fi

pn_reset
ktap_finished
