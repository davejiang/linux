#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) mbind() placement.  A private node opted into
# CAP_MEMPOLICY may be named in an MPOL_BIND mask; a non-opted private node is
# trimmed from the mask exactly like a cpuset-disallowed node (empty -> EINVAL).
# Either way nothing leaks onto a node outside the requested mask.
#
#   1. mbind(MPOL_BIND, {private}) onto an opted node places pages there.
#   2. mbind to two opted private nodes {P1,P2} is honored; pages stay on
#      private nodes (none on DRAM).                       (needs >=2)
#   3. mbind to a mixed {dram,P1} mask is honored; pages stay within the mask
#      (distance-preferred to DRAM), none leak elsewhere.
#   4. mbind to a non-opted private node is rejected (-EINVAL), via trimming.
#
# Needs anondax private node(s) on memoryless node(s).

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
pn_provision_all
set -- $PN_NODES
nprivate=$#
[ "$nprivate" -ge 1 ] || { ktap_skip_all "no anondax private node provisioned"; exit "$KSFT_SKIP"; }

# opt every provisioned private node into mempolicy placement + hot-unplug
for d in $PN_DAXES; do
	echo unplugged > "$DAX_BASE/$d/hotplug" 2>/dev/null
	echo 1 > "$DAX_BASE/$d/mempolicy" 2>/dev/null
	echo 1 > "$DAX_BASE/$d/hotunplug" 2>/dev/null
	echo online_movable > "$DAX_BASE/$d/hotplug" 2>/dev/null
done
sleep 1
P1=$(echo $PN_NODES | awk '{print $1}')
P2=$(echo $PN_NODES | awk '{print $2}')
D1=$(echo $PN_DAXES | awk '{print $1}')
DRAM0=$(awk -F, '{print $1}' "$NODE_BASE/has_memory"); DRAM0=${DRAM0%%-*}
node_in_mask "$P1" has_private_memory || { ktap_skip_all "node $P1 did not online as private"; exit "$KSFT_SKIP"; }
ktap_print_msg "private nodes={$PN_NODES} dram0=$DRAM0"
ktap_set_plan 4

# 1. single opted private bind: accepted and placed on the node
out=$("$TOOL" mbind "$P1" 16 2>&1); echo "$out" | sed 's/^/# /'
placed=$(echo "$out" | sed -n "s/.*on_node$P1=\([0-9]*\).*/\1/p")
total=$(echo "$out" | sed -n "s/.*total=\([0-9]*\).*/\1/p")
if echo "$out" | grep -q "rc=0" && [ "${placed:-0}" -gt 0 ] && [ "$placed" = "$total" ] 2>/dev/null; then
	ktap_test_pass "mbind({$P1}) placed all $placed pages on the private node"
else
	ktap_test_fail "mbind({$P1}) did not place on the private node ($out)"
fi

# 2. two opted private nodes: honored, and nothing lands on DRAM
if [ "$nprivate" -lt 2 ]; then
	ktap_test_skip "need >=2 private nodes for the multi-private mask check"
else
	out=$("$TOOL" mbindmask 16 "$P1" "$P2" 2>&1); echo "$out" | sed 's/^/# /'
	on1=$(echo "$out" | sed -n "s/.*on_node$P1=\([0-9]*\).*/\1/p")
	total=$(echo "$out" | sed -n "s/.*total=\([0-9]*\).*/\1/p")
	if echo "$out" | grep -q "rc=0" && [ "${on1:-0}" -gt 0 ] && [ "$on1" = "$total" ] 2>/dev/null; then
		ktap_test_pass "mbind({$P1,$P2}) honored; all $total pages on private nodes (none on DRAM)"
	else
		ktap_test_fail "mbind({$P1,$P2}) not honored or leaked off private ($out)"
	fi
fi

# 3. mixed regular+private: honored, pages stay within the mask (no leak)
out=$("$TOOL" mbindmask 16 "$DRAM0" "$P1" 2>&1); echo "$out" | sed 's/^/# /'
on0=$(echo "$out" | sed -n "s/.*on_node$DRAM0=\([0-9]*\).*/\1/p")
total=$(echo "$out" | sed -n "s/.*total=\([0-9]*\).*/\1/p")
if echo "$out" | grep -q "rc=0" && [ "${on0:-0}" -gt 0 ] && [ "$on0" = "$total" ] 2>/dev/null; then
	ktap_test_pass "mbind({$DRAM0,$P1}) honored; all $total pages within the mask (on DRAM)"
else
	ktap_test_fail "mbind({$DRAM0,$P1}) not honored or leaked ($out)"
fi

# 4. non-opted private node is trimmed -> empty mask -> EINVAL
echo unplugged > "$DAX_BASE/$D1/hotplug" 2>/dev/null
echo 0 > "$DAX_BASE/$D1/mempolicy" 2>/dev/null
echo online_movable > "$DAX_BASE/$D1/hotplug" 2>/dev/null
out=$("$TOOL" mbind "$P1" 16 2>&1); echo "$out" | sed 's/^/# /'
if echo "$out" | grep -q "errno=22"; then
	ktap_test_pass "mbind({$P1}) on a non-opted private node rejected EINVAL (trimmed)"
else
	ktap_test_fail "mbind({$P1}) non-opted not rejected ($out)"
fi

for d in $PN_DAXES; do echo unplugged > "$DAX_BASE/$d/hotplug" 2>/dev/null; done
ktap_finished
