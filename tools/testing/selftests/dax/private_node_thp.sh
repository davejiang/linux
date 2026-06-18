#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) THP collapse under CAP_RECLAIM.  khugepaged-style
# collapse is the THP cousin of compaction -- kernel-initiated, intra-node
# relocation of base pages into a huge folio -- so it follows the reclaim
# opt-in.  Collapse is triggered synchronously with MADV_COLLAPSE.
#
# Both subtests bind base pages onto the private node (needs CAP_MEMPOLICY) and
# then MADV_COLLAPSE:
#
#   1. opted in (mempolicy + reclaim): collapse succeeds and the resulting THP
#      sits on the private node (AnonHugePages > 0 on the node).
#   2. mempolicy but NOT reclaim: base pages still land on the node, but collapse
#      is refused -- no THP forms (AnonHugePages stays 0).
#
# Needs an anondax private node on a memoryless node (see private_node_common.sh).

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
pn_provision
[ -e "$D/mempolicy" ] || { ktap_skip_all "$DAX missing mempolicy cap attribute"; exit "$KSFT_SKIP"; }

up() {	# online PN with mempolicy=1 and reclaim=$1
	pn_reset
	pn_set hotunplug 1
	pn_set mempolicy 1
	pn_set reclaim "$1"
	pn_hotplug online_movable
}

up 1
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_skip_all "could not online node $PN as private"
	pn_reset; exit "$KSFT_SKIP"
fi
ktap_print_msg "using $DAX on private node $PN"
ktap_set_plan 2

# 1. mempolicy + reclaim: collapse allowed, THP lands on the private node.
out=$("$TOOL" collapse "$PN" 4 2>&1); echo "$out" | sed 's/^/# /'
post=$(echo "$out" | sed -n 's/.*post on_node'"$PN"'=\([0-9]*\).*AnonHugePages=\([0-9]*\)kB/\1 \2/p')
on_post=${post% *}; ahp_post=${post#* }
if [ "${ahp_post:-0}" -gt 0 ] 2>/dev/null && [ "${on_post:-0}" -gt 0 ] 2>/dev/null; then
	ktap_test_pass "collapse on opted (reclaim) private node $PN formed THP on-node (AnonHugePages=${ahp_post}kB)"
else
	ktap_test_fail "collapse on opted private node $PN did not form an on-node THP ($out)"
fi

# 2. mempolicy but reclaim cleared: base pages land, but collapse is refused.
up 0
if ! pn_is_private; then
	ktap_test_skip "node $PN did not re-online private after clearing reclaim"
	pn_reset; exit 0
fi
out=$("$TOOL" collapse "$PN" 4 2>&1); echo "$out" | sed 's/^/# /'
pre_on=$(echo "$out" | sed -n 's/.*pre  on_node'"$PN"'=\([0-9]*\).*/\1/p')
ahp_post=$(echo "$out" | sed -n 's/.*post on_node'"$PN"'=[0-9]*.*AnonHugePages=\([0-9]*\)kB/\1/p')
if [ "${pre_on:-0}" -gt 0 ] 2>/dev/null && [ "${ahp_post:-0}" -eq 0 ] 2>/dev/null; then
	ktap_test_pass "collapse refused on non-reclaim private node $PN (pages on-node, no THP)"
else
	ktap_test_fail "collapse not refused on non-reclaim private node $PN ($out)"
fi

pn_reset
ktap_finished
