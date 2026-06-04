#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Exercise the dax/kmem whole-device "hotplug" sysfs attribute:
#   /sys/bus/dax/devices/daxX.Y/hotplug  ->  unplugged | online | online_movable
#
# The test needs a dax device already bound to the kmem driver (so the
# 'hotplug' attribute exists).  Provisioning a devdax device and binding it to
# kmem requires daxctl/ndctl (or the tools/testing/nvdimm emulation) and is out
# of scope here; if no suitable device is found the test SKIPs.
#
# To actually run it, provision a kmem-backed dax device first.  For example,
# carve a chunk of RAM into an emulated pmem region via the kernel command line
# (the region must be at least one memory block, e.g. 128MiB on x86):
#
#   memmap=2G!4G
#
# then, in the booted system:
#
#   ndctl create-namespace -m devdax -e namespace0.0 -f
#   daxctl reconfigure-device -N -m system-ram dax0.0   # binds the kmem driver
#   ./dax-kmem-hotplug.sh

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh

DAX_BASE=/sys/bus/dax/devices

memtotal_kb() { awk '/^MemTotal:/ {print $2}' /proc/meminfo; }
get_state() { cat "$HP" 2>/dev/null; }
# set_state STATE -- write a state to the hotplug attribute; returns the
# write's exit status (0 = accepted by the kernel)
set_state() { echo "$1" > "$HP" 2>/dev/null; }

find_kmem_dax() {
	local d drv
	for d in "$DAX_BASE"/dax*; do
		[ -e "$d/hotplug" ] || continue
		drv=$(readlink "$d/driver" 2>/dev/null)
		[ "$(basename "${drv:-}")" = kmem ] || continue
		basename "$d"
		return 0
	done
	return 1
}

ktap_print_header

if [ "$UID" != 0 ]; then
	ktap_skip_all "must be run as root"
	exit "$KSFT_SKIP"
fi

DAX=$(find_kmem_dax)
if [ -z "$DAX" ]; then
	ktap_skip_all "no kmem-bound dax device with a hotplug attribute"
	exit "$KSFT_SKIP"
fi
HP=$DAX_BASE/$DAX/hotplug
ORIG=$(get_state)

# A failure to reach the baseline is environmental (memory in use), not an
# interface failure, so skip rather than fail.
set_state unplugged; rc=$?
if [ "$rc" != 0 ] || [ "$(get_state)" != unplugged ]; then
	ktap_skip_all "$DAX: cannot reach 'unplugged' baseline (memory in use?)"
	[ -n "$ORIG" ] && set_state "$ORIG"
	exit "$KSFT_SKIP"
fi
mt_unplugged=$(memtotal_kb)

ktap_print_msg "using $DAX (initial state was: $ORIG)"
ktap_set_plan 8

set_state online; rc=$?
mt_online=$(memtotal_kb)
if [ "$rc" = 0 ] && [ "$(get_state)" = online ] && [ "$mt_online" -gt "$mt_unplugged" ]; then
	ktap_test_pass "online: state=online, MemTotal $mt_unplugged -> $mt_online kB"
else
	ktap_test_fail "online: rc=$rc state=$(get_state) MemTotal $mt_unplugged -> $mt_online"
fi

set_state online; rc=$?
if [ "$rc" = 0 ] && [ "$(get_state)" = online ]; then
	ktap_test_pass "online idempotent"
else
	ktap_test_fail "online idempotent: rc=$rc state=$(get_state)"
fi

set_state online_movable; rc=$?
if [ "$rc" != 0 ] && [ "$(get_state)" = online ]; then
	ktap_test_pass "reject online_movable without intervening unplug"
else
	ktap_test_fail "online->online_movable not rejected: rc=$rc state=$(get_state)"
fi

set_state unplugged; rc=$?
mt=$(memtotal_kb)
if [ "$rc" = 0 ] && [ "$(get_state)" = unplugged ] && [ "$mt" -lt "$mt_online" ]; then
	ktap_test_pass "unplug from online: MemTotal $mt_online -> $mt kB"
else
	ktap_test_fail "unplug from online: rc=$rc state=$(get_state) MemTotal $mt_online -> $mt"
fi

set_state online_movable; rc=$?
mt_movable=$(memtotal_kb)
if [ "$rc" = 0 ] && [ "$(get_state)" = online_movable ] && [ "$mt_movable" -gt "$mt_unplugged" ]; then
	ktap_test_pass "online_movable after unplug: MemTotal $mt_unplugged -> $mt_movable kB"
else
	ktap_test_fail "online_movable after unplug: rc=$rc state=$(get_state) MemTotal=$mt_movable"
fi

# The online -> unplug -> online_movable -> unplug cycle once regressed: a
# re-online failed to re-reserve the per-range resources, so this final unplug
# reported success while leaving the memory online.  Assert it is really freed.
set_state unplugged; rc=$?
mt=$(memtotal_kb)
if [ "$rc" != 0 ]; then
	ktap_test_skip "unplug from movable not accepted (memory in use?) rc=$rc"
elif [ "$(get_state)" = unplugged ] && [ "$mt" -lt "$mt_movable" ]; then
	ktap_test_pass "unplug from online_movable removed memory: $mt_movable -> $mt kB"
else
	ktap_test_fail "unplug from movable reported success but memory remained: state=$(get_state) MemTotal $mt_movable -> $mt"
fi

set_state online_kernel; rc=$?
mt=$(memtotal_kb)
if [ "$rc" = 0 ] && [ "$(get_state)" = online_kernel ] && [ "$mt" -gt "$mt_unplugged" ]; then
	ktap_test_pass "online_kernel: MemTotal $mt_unplugged -> $mt kB"
else
	ktap_test_fail "online_kernel: rc=$rc state=$(get_state) MemTotal=$mt"
fi
set_state unplugged

before=$(get_state)
set_state bogus_state; rc=$?
if [ "$rc" != 0 ] && [ "$(get_state)" = "$before" ]; then
	ktap_test_pass "reject invalid state string"
else
	ktap_test_fail "invalid state not rejected: rc=$rc state=$(get_state)"
fi

[ -n "$ORIG" ] && set_state "$ORIG"

ktap_finished
