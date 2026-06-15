#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) NODE_PRIVATE_CAP_LTPIN test.
#
# A FOLL_LONGTERM pin of a folio on a private node that did NOT opt into
# longterm pinning must fail outright and leave the folio in place - it is
# neither pinnable nor migratable.  Opting the node in (ltpin=1) makes such a
# pin succeed like ordinary memory.
#
# Drives the pin via the gup_test debugfs PIN_LONGTERM_TEST_START ioctl, so it
# needs CONFIG_GUP_TEST=y and debugfs mounted; SKIPs otherwise.  Also needs an
# anondax-bindable dax device on a memoryless node (see private_node_common.sh).

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
grep -q debugfs /proc/mounts || mount -t debugfs none /sys/kernel/debug 2>/dev/null
[ -e /sys/kernel/debug/gup_test ] ||
	{ ktap_skip_all "gup_test unavailable (need CONFIG_GUP_TEST=y)"; exit "$KSFT_SKIP"; }
pn_provision
ktap_print_msg "using $DAX on private node $PN"

# ltpin needs CAP_MBIND too, so userspace can place anon memory on the node.
ltpin_run() {	# $1 = ltpin opt-in (0/1) ; echoes the tool's verdict line
	pn_reset
	pn_set mempolicy 1
	pn_set ltpin "$1"
	pn_hotplug online_kernel
	"$TOOL" ltpin "/dev/$DAX" 8 "$PN"
	pn_hotplug unplugged
}

if ! pn_set mempolicy 1 || [ "$(pn_get mempolicy)" != 1 ]; then
	ktap_skip_all "$DAX has no mempolicy opt-in (NODE_PRIVATE_CAP_MEMPOLICY)"
	exit "$KSFT_SKIP"
fi
pn_reset
ktap_set_plan 2

# 1. opted OUT: pin must fail and the folio must not be migrated off the node
out=$(ltpin_run 0)
pinned=$(echo "$out" | sed -n 's/.*pinned=\([a-z]*\).*/\1/p')
total=$(echo "$out" | sed -n 's/.*total_pages=\([0-9]*\).*/\1/p')
onnode=$(echo "$out" | sed -n "s/.*on_node$PN=\([0-9]*\).*/\1/p")
if [ "$pinned" = no ] && [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$onnode" = "$total" ]; then
	ktap_test_pass "opted-out: longterm pin rejected, folios not migrated ($out)"
else
	ktap_test_fail "opted-out pin not handled correctly ($out)"
fi

# 2. opted IN: pin succeeds
out=$(ltpin_run 1)
pinned=$(echo "$out" | sed -n 's/.*pinned=\([a-z]*\).*/\1/p')
if [ "$pinned" = yes ]; then
	ktap_test_pass "opted-in: longterm pin succeeded ($out)"
else
	ktap_test_fail "opted-in pin did not succeed ($out)"
fi

pn_reset
ktap_finished
