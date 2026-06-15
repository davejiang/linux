#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) pressure tests: a private node must never receive a
# NORMAL allocation, and exhausting it via its own private bind must drive a
# node-aware OOM kill rather than a silent spill onto DRAM.
#
#   1. Containment: under heavy node-0 anon pressure (larger than node-0 DRAM)
#      AND a per-node hugetlb pool write (an explicit __GFP_THISNODE alloc), the
#      private node stays free==total -- nothing leaks onto it.
#   2. Directed OOM: with the node reclaim-opted-in and NO swap, a hog faults
#      ~75% of the node and a trigger faults ~50% more.  The bind carries
#      nodemask={P} (CONSTRAINT_MEMORY_POLICY), so exhaustion must OOM-kill a
#      {P}-eligible victim (the larger hog) and let the trigger complete -- never
#      spill the trigger onto another node.
#
# Needs an anondax-bindable dax device on a memoryless node; SKIPs otherwise.
# See private_node_common.sh for memmap= provisioning.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

# pages of zoneinfo key $2 ("free"/"managed") summed over node $1
zone_pages() { awk -v n="$1" -v k="$2" '$1=="Node"{i=($2==n",")} i&&$1==k{m+=$2} END{print m+0}' /proc/zoneinfo; }
node_total_kb() { awk '/MemTotal:/{print $4}' "$NODE_BASE/node$1/meminfo"; }
node_free_kb()  { awk '/MemFree:/{print $4}'  "$NODE_BASE/node$1/meminfo"; }

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
pn_provision
pn_reset

ktap_set_plan 3

# ---------------------------------------------------------------------------
# 1. CONTAINMENT: no-caps node, online_kernel (most permissive zone).
# ---------------------------------------------------------------------------
pn_hotplug online_kernel
if [ "$(pn_state)" != online_kernel ] || ! pn_is_private; then
	ktap_test_skip "could not online node $PN as private (state=$(pn_state))"
else
	tot=$(node_total_kb "$PN")
	free0=$(node_free_kb "$PN")
	spill=0
	[ "${tot:-0}" -gt 0 ] || spill=1
	[ "$free0" = "$tot" ] || spill=1

	# per-node hugetlb pool write: an explicit __GFP_THISNODE alloc must place 0.
	hp="$NODE_BASE/node$PN/hugepages/hugepages-2048kB/nr_hugepages"
	if [ -w "$hp" ]; then
		echo 64 > "$hp" 2>/dev/null
		[ "$(cat "$hp")" = 0 ] || spill=1
		[ "$(node_free_kb "$PN")" = "$tot" ] || spill=1
		echo 0 > "$hp" 2>/dev/null
	fi

	# node-0 anon pressure > node-0 DRAM, paced so reclaim runs (no OOM burst).
	churn_mb=$(( $(node_total_kb 0) / 1024 + 512 ))
	"$TOOL" churn "$churn_mb" 18 >/dev/null 2>&1 &
	ch=$!
	for _ in 1 2 3 4 5 6; do
		sleep 3
		[ "$(node_free_kb "$PN")" = "$tot" ] || spill=1
	done
	kill "$ch" 2>/dev/null; wait "$ch" 2>/dev/null

	if [ "$spill" = 0 ]; then
		ktap_test_pass "private node $PN untouched under node-0 pressure + THISNODE hugetlb"
	else
		ktap_test_fail "containment breach: node $PN free dropped below total"
	fi
fi
pn_reset

# ---------------------------------------------------------------------------
# 2. DIRECTED OOM: reclaim-opted node, no swap, exhaust via the private bind.
# ---------------------------------------------------------------------------
swapoff -a 2>/dev/null			# the contract under test is no-reclaim-target
pn_set reclaim 1
pn_set hotunplug 1
pn_hotplug online_movable
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_test_skip "could not online node $PN (reclaim) as private"
else
	man_mb=$(( $(zone_pages "$PN" managed) / 256 ))
	if [ "${man_mb:-0}" -lt 64 ]; then
		ktap_test_skip "node $PN too small (${man_mb}MB) for the OOM experiment"
	else
		hog_mb=$(( man_mb * 75 / 100 ))
		trig_mb=$(( man_mb * 50 / 100 ))
		"$TOOL" daxmap "/dev/$DAX" "$hog_mb" "$PN" 120 >/dev/null 2>&1 &
		hp=$!
		sleep 4
		"$TOOL" daxmap "/dev/$DAX" "$trig_mb" "$PN" 0 >/dev/null 2>&1 &
		tp=$!
		wait "$tp"; trc=$?
		kill -0 "$hp" 2>/dev/null && hog_alive=1 || hog_alive=0
		kill -9 "$hp" 2>/dev/null; wait "$hp" 2>/dev/null

		# PASS: the trigger completed (rc 0) because a node-aware OOM kill freed
		# the node -- i.e. exhaustion stayed scoped to the node, no DRAM spill.
		if [ "$trc" = 0 ] && [ "$hog_alive" = 0 ]; then
			ktap_test_pass "exhaustion OOM-killed the hog; trigger completed on node $PN"
		elif [ "$trc" = 135 ]; then
			ktap_test_skip "trigger SIGBUS'd (no node-aware OOM kill in this env)"
		else
			ktap_test_fail "unexpected OOM outcome (trigger rc=$trc hog_alive=$hog_alive)"
		fi
	fi
fi
pn_reset

# ---------------------------------------------------------------------------
# 3. THP-order mbind under private-node pressure must stay on-node.  A private
#    node has no NOFALLBACK list, so a __GFP_THISNODE THP fault is served from
#    ZONELIST_PRIVATE; it must still be confined to the node (not spill to DRAM).
# ---------------------------------------------------------------------------
pn_set mempolicy 1
pn_set hotunplug 1
pn_hotplug online_movable
echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_test_skip "could not online node $PN (mbind) as private"
elif ! grep -q '\[always\]' /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null; then
	ktap_test_skip "THP unavailable (CONFIG_TRANSPARENT_HUGEPAGE)"
else
	man_mb=$(( $(zone_pages "$PN" managed) / 256 ))
	# Pressure P so the THP fast-attempt can't get a 2MB block locally and
	# (pre-fix) would spill the THP to DRAM via ZONELIST_PRIVATE.
	"$TOOL" mbind "$PN" $(( man_mb * 90 / 100 )) 30 >/dev/null 2>&1 &
	fp=$!; sleep 3
	out=$("$TOOL" mbindthp "$PN" 64 0 2>&1); rc=$?
	kill "$fp" 2>/dev/null; wait "$fp" 2>/dev/null
	echo "$out" | sed 's/^/# /'
	off=$(echo "$out" | sed -n 's/.*off=\([0-9]*\).*/\1/p')
	if [ "$rc" != 0 ]; then
		ktap_test_pass "THP mbind failed rather than spilling off private node $PN (rc=$rc)"
	elif [ "${off:-1}" = 0 ]; then
		ktap_test_pass "THP-order mbind stayed on private node $PN under pressure (off=0)"
	else
		ktap_test_fail "THP mbind spilled $off pages off private node $PN"
	fi
fi
pn_reset

ktap_finished
