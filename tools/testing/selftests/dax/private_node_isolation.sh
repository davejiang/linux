#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) placement test: memory mapped from an anondax dax
# device must land on its private node (the driver stamps an MPOL_F_PRIVATE
# bind via ->get_policy), and the device must reject MAP_SHARED.
#
# Needs an anondax-bindable dax device on a memoryless node; SKIPs otherwise.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
pn_provision
pn_reset

# Bring the node up as a cleanly-unpluggable ZONE_MOVABLE node: hotunplug lets
# teardown migrate any residue off, so unplug never EBUSYs.  Placement itself
# needs no opt-in: the device's private bind steers faults onto the node.
pn_set hotunplug 1
pn_hotplug online_movable
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_skip_all "$DAX: could not online node $PN as private (state=$(pn_state))"
	pn_reset; exit "$KSFT_SKIP"
fi
ktap_print_msg "using $DAX on private node $PN"
ktap_set_plan 2

# 1. faulted pages are resident on the private node
out=$("$TOOL" map "/dev/$DAX" 64 "$PN"); rc=$?
total=$(echo "$out" | sed -n 's/.*total_pages=\([0-9]*\).*/\1/p')
onnode=$(echo "$out" | sed -n "s/.*on_node$PN=\([0-9]*\).*/\1/p")
if [ "$rc" = "$KSFT_SKIP" ]; then
	ktap_test_skip "mmap/fault unavailable: $out"
elif [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$onnode" = "$total" ]; then
	ktap_test_pass "all $total faulted pages resident on private node $PN"
else
	ktap_test_fail "off-node placement: on_node$PN=$onnode of total=$total ($out)"
fi

# 2. MAP_SHARED is rejected (anondax mappings are private by definition)
out=$("$TOOL" shared "/dev/$DAX")
if echo "$out" | grep -q 'shared_mmap=rejected'; then
	ktap_test_pass "MAP_SHARED rejected ($out)"
else
	ktap_test_fail "MAP_SHARED not rejected ($out)"
fi

pn_reset
ktap_finished
