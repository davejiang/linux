#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) mempolicy placement under CAP_MEMPOLICY: set_mempolicy/
# mbind nodemask placement is gated uniformly; home_node is NOT gated -- it is
# only a preferred-nid hint, so a home node on a non-opted private node is
# accepted and simply falls back (placement stays governed by the bind nodemask).
#
#   1. set_mempolicy(MPOL_BIND, {private}) onto an opted node is accepted
#      (honored via the same chokepoint as mbind).  NB: we only validate the
#      gate, not placement -- a process-wide strict bind to a ZONE_MOVABLE
#      private node would wedge unmovable (page-table) allocations.
#   2. set_mempolicy_home_node() accepts an opted private node as a home node.
#   3. process-wide MPOL_BIND to a movable-only private node falls back (no wedge).
#   4. With the opt-in cleared, set_mempolicy({private}) is rejected (-EINVAL),
#      trimmed like a cpuset-disallowed node.
#   5. ...but the private node is still accepted as a home node (home_node is
#      not CAP-gated) and nothing lands on it -- it falls back to the bind node.
#
# move_pages() is gated separately by CAP_USER_MIGRATE; see
# private_node_user_migrate.sh.  Needs an anondax private node on a memoryless node.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
pn_provision
DRAM0=$(awk -F, '{print $1}' "$NODE_BASE/has_memory"); DRAM0=${DRAM0%%-*}

up() {	# bring PN up with mempolicy opt-in = $1
	pn_reset
	pn_set hotunplug 1
	pn_set mempolicy "$1"
	pn_hotplug online_movable
}

up 1
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_skip_all "could not online node $PN (mempolicy) as private"
	pn_reset; exit "$KSFT_SKIP"
fi
ktap_print_msg "using $DAX on private node $PN, dram0=$DRAM0"
ktap_set_plan 5

# 1. set_mempolicy(MPOL_BIND, {private}) accepted for an opted private node
out=$("$TOOL" setmempol "$PN" 16 2>&1); echo "$out" | sed 's/^/# /'
if echo "$out" | grep -q "rc=0"; then
	ktap_test_pass "set_mempolicy(MPOL_BIND,{$PN}) accepted for opted private node"
else
	ktap_test_fail "set_mempolicy({$PN}) rejected despite opt-in ($out)"
fi

# 2. opted private node accepted as a home node (bound to DRAM, so it lands there)
out=$("$TOOL" sethome "$PN" "$DRAM0" 16 2>&1); echo "$out" | sed 's/^/# /'
if echo "$out" | grep -q "rc=0" && echo "$out" | grep -q "on_home$PN=0"; then
	ktap_test_pass "set_mempolicy_home_node($PN) accepted for opted private node"
else
	ktap_test_fail "home_node($PN) rejected/misplaced despite opt-in ($out)"
fi

# 3. a process-wide MPOL_BIND to a movable-only private node must not livelock:
#    its unmovable allocations (page tables) have no usable zone on the node and
#    must fall back to real memory, not VM_FAULT_OOM-retry forever.  Watchdog so a
#    regression reports FAIL instead of hanging.
"$TOOL" bindfault "$PN" 16 >/tmp/pn_bf.$$ 2>&1 & bfp=$!
for _ in $(seq 1 15); do sleep 1; kill -0 "$bfp" 2>/dev/null || break; done
if kill -0 "$bfp" 2>/dev/null; then
	kill -9 "$bfp" 2>/dev/null
	ktap_test_fail "process-wide MPOL_BIND({$PN}) livelocked (unmovable alloc not falling back)"
elif grep -q "bindfault: done" /tmp/pn_bf.$$; then
	sed 's/^/# /' /tmp/pn_bf.$$
	ktap_test_pass "process-wide MPOL_BIND({$PN}) completed; unmovable allocs fell back to real memory"
else
	ktap_test_skip "bindfault inconclusive ($(tr '\n' ';' </tmp/pn_bf.$$))"
fi
rm -f /tmp/pn_bf.$$

# clear the opt-in and re-online
up 0
if ! pn_is_private; then
	ktap_test_skip "node $PN did not re-online private after clearing opt-in"
	ktap_test_skip "(non-opted home-node check skipped)"
	pn_reset; exit 0
fi

# 4. non-opted: set_mempolicy({private}) trimmed -> EINVAL
out=$("$TOOL" setmempol "$PN" 16 2>&1); echo "$out" | sed 's/^/# /'
if echo "$out" | grep -q "errno=22"; then
	ktap_test_pass "set_mempolicy({$PN}) on a non-opted private node rejected EINVAL"
else
	ktap_test_fail "set_mempolicy({$PN}) non-opted not rejected ($out)"
fi

# 5. non-opted: home_node is NOT cap-gated -- accepted, and nothing lands on the
#    private node (placement is governed by the bind nodemask, not home_node).
out=$("$TOOL" sethome "$PN" "$DRAM0" 16 2>&1); echo "$out" | sed 's/^/# /'
if echo "$out" | grep -q "rc=0" && echo "$out" | grep -q "on_home$PN=0"; then
	ktap_test_pass "set_mempolicy_home_node($PN) accepted for non-opted private node; fell back off it"
else
	ktap_test_fail "home_node($PN) non-opted: expected accept + fallback off node ($out)"
fi

pn_reset
ktap_finished
