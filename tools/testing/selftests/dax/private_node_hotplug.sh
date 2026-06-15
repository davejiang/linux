#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) capability + hotplug ABI test.
#
# anondax exposes, per dax device, a "hotplug" state attribute and one bool
# attribute per NODE_PRIVATE_CAP_* opt-in (reclaim, mempolicy, hotunplug,
# tiering, ltpin).  The opt-ins are recorded
# while the device is unplugged and applied to the node at hotplug.
#
# Capability *dependencies* (e.g. tiering requires reclaim) are
# enforced once, by node_private_register() at hotplug - NOT by the sysfs
# setters.  So an inconsistent combination is accepted at write time but fails
# to plug in.  This test pins that contract.
#
# Needs an anondax-bindable dax device on a memoryless node; SKIPs otherwise.
# See private_node_common.sh for memmap= provisioning.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

ktap_print_header
pn_require_root
pn_provision
ktap_print_msg "using $DAX on private node $PN (state was: $(pn_state))"
pn_reset
if [ "$(pn_state)" != unplugged ]; then
	ktap_skip_all "$DAX: cannot reach 'unplugged' baseline (memory in use?)"
	exit "$KSFT_SKIP"
fi

ktap_set_plan 8

# 1. an opt-in is writable while unplugged and reads back
pn_set reclaim 1
if [ "$(pn_get reclaim)" = 1 ]; then
	ktap_test_pass "reclaim opt-in recorded while unplugged"
else
	ktap_test_fail "reclaim opt-in not recorded: reclaim=$(pn_get reclaim)"
fi

# 2. a bogus bool value is rejected
before=$(pn_get reclaim)
pn_set reclaim maybe; rc=$?
if [ "$rc" != 0 ] && [ "$(pn_get reclaim)" = "$before" ]; then
	ktap_test_pass "invalid bool value rejected (reclaim unchanged)"
else
	ktap_test_fail "invalid bool not rejected: rc=$rc reclaim=$(pn_get reclaim)"
fi

# 3. dependency enforced at hotplug, not at write: tiering without reclaim is
#    accepted by the setter ...
pn_reset
pn_set tiering 1; rc=$?
if [ "$rc" = 0 ] && [ "$(pn_get tiering)" = 1 ]; then
	ktap_test_pass "tiering without reclaim accepted at write (rc=0)"
else
	ktap_test_fail "tiering write unexpectedly rejected: rc=$rc"
fi

# 4. ... but the inconsistent combination fails to plug in and leaves the node
#    non-private.
pn_hotplug online_kernel; rc=$?
if [ "$rc" != 0 ] && [ "$(pn_state)" = unplugged ] && ! pn_is_private; then
	ktap_test_pass "tiering without reclaim rejected at hotplug (node stays private=0)"
else
	ktap_test_fail "inconsistent caps plugged in: rc=$rc state=$(pn_state) private=$(pn_is_private && echo 1 || echo 0)"
fi

# 5. satisfying the dependency lets it plug in and the node becomes private
pn_set reclaim 1
pn_hotplug online_kernel; rc=$?
if [ "$rc" = 0 ] && [ "$(pn_state)" = online_kernel ] && pn_is_private; then
	ktap_test_pass "reclaim+tiering plugs in; node $PN is now N_MEMORY_PRIVATE"
else
	ktap_test_fail "consistent caps failed to plug in: rc=$rc state=$(pn_state) private=$(pn_is_private && echo 1 || echo 0)"
fi

# 6. opt-ins are read-only (EBUSY) while plugged in
pn_set mempolicy 1; rc=$?
if [ "$rc" != 0 ] && [ "$(pn_get mempolicy)" = 0 ]; then
	ktap_test_pass "opt-in write rejected while plugged in (EBUSY)"
else
	ktap_test_fail "opt-in mutated while online: rc=$rc mbind=$(pn_get mempolicy)"
fi

# 7. unplug clears the private state
pn_hotplug unplugged; rc=$?
if [ "$rc" = 0 ] && [ "$(pn_state)" = unplugged ] && ! pn_is_private; then
	ktap_test_pass "unplug clears N_MEMORY_PRIVATE on node $PN"
else
	ktap_test_fail "unplug did not clear private state: rc=$rc state=$(pn_state) private=$(pn_is_private && echo 1 || echo 0)"
fi

# 8. an invalid hotplug state string is rejected
before=$(pn_state)
pn_hotplug bogus_state; rc=$?
if [ "$rc" != 0 ] && [ "$(pn_state)" = "$before" ]; then
	ktap_test_pass "invalid hotplug state string rejected"
else
	ktap_test_fail "invalid state not rejected: rc=$rc state=$(pn_state)"
fi

pn_reset
ktap_finished
