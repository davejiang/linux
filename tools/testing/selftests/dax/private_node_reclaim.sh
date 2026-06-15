#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) reclaim tests.  A private node opts into reclaim; its
# folios carry the device's MPOL_F_PRIVATE bind via ->get_policy.
#
#   1. Swap round-trip: fault onto the node, MADV_PAGEOUT, evict the swap cache
#      off the node, then read back -- the swap-in path (do_swap_page, which
#      never calls ->fault) must replace the folios BACK on the private node,
#      not bleed them onto DRAM, with data intact.
#   2. MADV_PAGEOUT is userland-driven reclaim, so it honours CAP_RECLAIM: with
#      reclaim opted in, pageout of node folios swaps them out (pswpout grows);
#      with it cleared, pageout of node folios is a no-op (pswpout flat).
#
# Needs an anondax dax device on a memoryless node AND a usable swap device
# (e.g. a vng --disk); SKIPs otherwise.  See private_node_common.sh.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool
MB=64

pswpout() { awk '/^pswpout /{print $2}' /proc/vmstat; }
zone_pages() { awk -v n="$1" -v k="$2" '$1=="Node"{i=($2==n",")} i&&$1==k{m+=$2} END{print m+0}' /proc/zoneinfo; }

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
pn_provision
pn_reset
pn_swap_setup || { ktap_skip_all "no usable swap device (attach a vng --disk)"; pn_reset; exit "$KSFT_SKIP"; }

pn_set reclaim 1
pn_set hotunplug 1
pn_hotplug online_movable
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_skip_all "could not online node $PN (reclaim) as private"
	pn_reset; exit "$KSFT_SKIP"
fi
ktap_print_msg "using $DAX on private node $PN with swap"
ktap_set_plan 2

# 1. swap round-trip back onto the private node
evict_mb=$(( $(zone_pages "$PN" managed) / 256 + 128 ))
"$TOOL" daxswap "/dev/$DAX" "$PN" "$MB" "$evict_mb" >/tmp/pn_daxswap.$$ 2>&1
rc=$?
sed 's/^/# /' /tmp/pn_daxswap.$$; rm -f /tmp/pn_daxswap.$$
case "$rc" in
0) ktap_test_pass "swapped-out folios refaulted back onto private node $PN, data intact" ;;
2) ktap_test_skip "swap round-trip inconclusive (no swap-in / cache not dropped)" ;;
*) ktap_test_fail "folios bled off node $PN on swap-in (rc=$rc)" ;;
esac

# 2. MADV_PAGEOUT (userland reclaim) gated by CAP_RECLAIM
p0=$(pswpout); "$TOOL" daxmadv "/dev/$DAX" 200 pageout >/dev/null 2>&1
on=$(( $(pswpout) - p0 ))
pn_hotplug unplugged; sleep 1
pn_set reclaim 0
pn_hotplug online_movable
p0=$(pswpout); "$TOOL" daxmadv "/dev/$DAX" 200 pageout >/dev/null 2>&1
off=$(( $(pswpout) - p0 ))
ktap_print_msg "pswpout delta: reclaim=1 -> $on, reclaim=0 -> $off"
if [ "$on" -gt 0 ] && [ "$off" -le $(( on / 4 + 16 )) ]; then
	ktap_test_pass "MADV_PAGEOUT reclaims node folios only when CAP_RECLAIM is set"
else
	ktap_test_fail "CAP_RECLAIM gate wrong (on=$on off=$off)"
fi

pn_reset
ktap_finished
