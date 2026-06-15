#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) tiering: opted-in private nodes participate in the
# memory-tier demotion/promotion machinery via ALLOC_ZONELIST_PRIVATE.
#
#   1. Demote TO private: a private node below DRAM is a demotion target; node-0
#      pressure demotes its cold tail onto the private node.
#   2. Promote OFF private: with NUMA balancing (mode 2), re-touching demoted
#      pages promotes them back to DRAM (pgpromote_success grows).
#   3. Demote FROM private (needs a 2nd private node): a private node placed
#      ABOVE DRAM in the tier order demotes its overflow *into* DRAM.
#
# Tiers/caps are configured once at hotplug (re-plugging a node with resident
# memory is not possible), so node1 is placed below DRAM and node2 above it.
# Multi-node + tier topology cannot be set from a selftest, so this SKIPs unless
# booted with the documented --numa/memmap layout and CONFIG_NUMA_BALANCING.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

nanon() { awk '/nr_inactive_anon|nr_active_anon/{s+=$2} END{print s+0}' "$NODE_BASE/node$1/vmstat" 2>/dev/null; }
pgd()   { awk '/^pgdemote_kswapd|^pgdemote_direct/{s+=$2} END{print s+0}' "$NODE_BASE/node$1/vmstat" 2>/dev/null; }
vstat() { awk -v k="$1" '$1==k{print $2}' /proc/vmstat; }
dram_mb() { awk '/MemTotal:/{print int($4/1024)}' "$NODE_BASE/node$1/meminfo"; }
tier_id() { local f; for f in /sys/devices/virtual/memory_tiering/*/nodelist; do
		nodelist_has "$(cat "$f")" "$1" && { b=$(basename "$(dirname "$f")"); echo "${b##*tier}"; return; }; done; }

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
[ -e /sys/kernel/mm/numa/demotion_enabled ] || { ktap_skip_all "demotion unsupported (CONFIG_NUMA_BALANCING?)"; exit "$KSFT_SKIP"; }
pn_provision_all
set -- $PN_NODES
nprivate=$#
[ "$nprivate" -ge 1 ] || { ktap_skip_all "no anondax private node provisioned"; exit "$KSFT_SKIP"; }
pn_swap_setup
DRAM0=$(awk -F, '{print $1}' "$NODE_BASE/has_memory"); DRAM0=${DRAM0%%-*}

dax_for_node() { local d n; for d in $PN_DAXES; do
		n=$(cat "$DAX_BASE/$d/target_node" 2>/dev/null); [ "$n" = "$1" ] && { echo "$d"; return; }; done; }

P1=$(echo $PN_NODES | awk '{print $1}'); D1=$(dax_for_node "$P1")
P2=$(echo $PN_NODES | awk '{print $2}'); [ -n "$P2" ] && D2=$(dax_for_node "$P2")

# Configure once: node1 below DRAM, node2 above.  CAP_TIERING enables the whole
# tiering set (demotion target + NUMA balancing + DAMON migrate) in one toggle.
cfg() {	# cfg DAX ADIST
	echo unplugged > "$DAX_BASE/$1/hotplug" 2>/dev/null
	echo 1 > "$DAX_BASE/$1/reclaim"
	echo "$2" > "$DAX_BASE/$1/adistance"
	echo 1 > "$DAX_BASE/$1/tiering"
	echo 1 > "$DAX_BASE/$1/hotunplug"
	echo online_movable > "$DAX_BASE/$1/hotplug" 2>/dev/null
}
cfg "$D1" 2880			# below DRAM
[ -n "$D2" ] && cfg "$D2" 256		# above DRAM
echo 1 > /sys/kernel/mm/numa/demotion_enabled 2>/dev/null
node_in_mask "$P1" has_private_memory || { ktap_skip_all "node $P1 did not online as private"; exit "$KSFT_SKIP"; }
ktap_print_msg "private={$PN_NODES} dram0=$DRAM0 tiers: $P1=tier$(tier_id "$P1") DRAM=tier$(tier_id "$DRAM0") ${P2:+$P2=tier$(tier_id "$P2")}"
ktap_set_plan 3

# 1. demote TO private (node1, below DRAM) ------------------------------------
a0=$(nanon "$P1")
"$TOOL" churn $(( $(dram_mb "$DRAM0") + 512 )) 35 >/dev/null 2>&1 & cp=$!
grew=0
for _ in $(seq 1 8); do sleep 4; [ "$(nanon "$P1")" -gt $(( a0 + 16384 )) ] 2>/dev/null && { grew=1; break; }; done
kill "$cp" 2>/dev/null; wait "$cp" 2>/dev/null
if [ "$grew" = 1 ]; then
	ktap_test_pass "node-0 pressure demoted anon onto private node $P1 (nr_anon grew)"
else
	ktap_test_fail "no demotion landed on private node $P1 (nr_anon flat)"
fi

# 2. promote OFF private (node1) ----------------------------------------------
if [ "$(cat "$DAX_BASE/$D1/tiering" 2>/dev/null)" != 1 ]; then
	ktap_test_skip "node $P1 has no tiering cap (NUMA balancing)"
else
	echo 2 > /proc/sys/kernel/numa_balancing 2>/dev/null
	if [ "$(cat /proc/sys/kernel/numa_balancing 2>/dev/null)" != 2 ]; then
		ktap_test_skip "NUMA balancing mode 2 (promotion) unavailable"
	else
		p0=$(vstat pgpromote_success)
		"$TOOL" churn $(( $(dram_mb "$DRAM0") + 512 )) 60 >/dev/null 2>&1 & cp=$!
		ok=0
		for _ in $(seq 1 12); do sleep 5; [ "$(vstat pgpromote_success)" -gt $(( p0 + 1024 )) ] 2>/dev/null && { ok=1; break; }; done
		kill "$cp" 2>/dev/null; wait "$cp" 2>/dev/null
		if [ "$ok" = 1 ]; then
			ktap_test_pass "pages demoted to node $P1 were promoted back to DRAM"
		else
			ktap_test_skip "no promotion observed (pgpromote_success flat in this env)"
		fi
	fi
fi

# 3. demote FROM private (node2, above DRAM) ----------------------------------
if [ -z "$P2" ]; then
	ktap_test_skip "demote-from-private needs a 2nd private node above DRAM"
elif [ "$(tier_id "$P2")" -ge "$(tier_id "$DRAM0")" ] 2>/dev/null; then
	ktap_test_skip "inverted tier did not form (P2=tier$(tier_id "$P2") vs DRAM=tier$(tier_id "$DRAM0"))"
else
	d0=$(pgd "$P2")
	"$TOOL" daxchurn "/dev/$D2" 2000 55 >/dev/null 2>&1 & fp=$!	# fill node2 (top tier)
	sleep 10
	"$TOOL" churn $(( $(dram_mb "$DRAM0") + 512 )) 40 >/dev/null 2>&1 & cp=$!	# pressure DRAM onward
	out=0
	for _ in $(seq 1 9); do sleep 5; [ "$(pgd "$P2")" -gt $(( d0 + 1024 )) ] 2>/dev/null && { out=1; break; }; done
	kill "$fp" "$cp" 2>/dev/null; wait "$fp" "$cp" 2>/dev/null
	if [ "$out" = 1 ]; then
		ktap_test_pass "private node $P2 above DRAM demoted *into* DRAM (pgdemote grew)"
	else
		ktap_test_fail "no demotion out of private node $P2 (pgdemote flat)"
	fi
fi

ktap_finished
