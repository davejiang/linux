#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Private-node (anondax) cpuset enforcement.  cpuset.mems is authoritative: a
# private bind is honored only while the node stays in the task's cpuset.mems.
# Once the node is dropped the bind is unsatisfiable, so a fault falls back to
# the cpuset-allowed memory (DRAM) rather than killing the task -- "ask for a
# node the cpuset forbids, get whatever the cpuset does allow."
#
#   1. Rebind: a task with the private node in its cpuset faults the anondax
#      mapping (lands on the private node), then the node is dropped from
#      cpuset.mems; the next fault spills off the private node onto allowed DRAM.
#   2. Foreign cpuset: a task whose cpuset.mems never included the private node
#      calls mbind(MPOL_BIND,{private}) -- it must place 0 pages there (mbind
#      rejected at the syscall, so nothing lands on the private node).
#
# Needs an anondax dax device on a memoryless node AND cgroup2 cpuset; SKIPs
# otherwise.  See private_node_common.sh.

DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR"/private_node_tool

ktap_print_header
pn_require_root
[ -x "$TOOL" ] || { ktap_skip_all "private_node_tool not built"; exit "$KSFT_SKIP"; }
pn_provision
pn_reset

CG=$(pn_cgroup2) || { ktap_skip_all "cgroup2 cpuset unavailable"; pn_reset; exit "$KSFT_SKIP"; }

pn_set mempolicy 1
pn_set hotunplug 1
pn_hotplug online_movable
if [ "$(pn_state)" != online_movable ] || ! pn_is_private; then
	ktap_skip_all "could not online node $PN (mbind) as private"
	pn_reset; exit "$KSFT_SKIP"
fi

CPUS=$(cat "$CG/cpuset.cpus.effective")
DRAM=$(cat "$NODE_BASE/has_memory")		# N_MEMORY nodes (private excluded)
ktap_print_msg "private node $PN; DRAM nodes=$DRAM cpus=$CPUS"
ktap_set_plan 2

# 1. rebind: include P, fault, drop P, refault -> spill off P onto allowed DRAM
g="$CG/pn_rebind"
mkdir -p "$g" 2>/dev/null
echo "$CPUS" > "$g/cpuset.cpus" 2>/dev/null
echo "$DRAM,$PN" > "$g/cpuset.mems" 2>/dev/null
if ! nodelist_has "$(cat "$g/cpuset.mems.effective")" "$PN"; then
	ktap_test_skip "cpuset would not accept private node $PN in mems (got $(cat "$g/cpuset.mems.effective"))"
else
	( echo $BASHPID > "$g/cgroup.procs"; exec "$TOOL" daxcpuset "/dev/$DAX" 32 "$PN" ) >/tmp/pn_cpuset.$$ 2>&1 &
	tp=$!
	sleep 2
	echo "$DRAM" > "$g/cpuset.mems" 2>/dev/null	# drop P mid-flight
	wait "$tp"; rc=$?
	sed 's/^/# /' /tmp/pn_cpuset.$$; rm -f /tmp/pn_cpuset.$$
	# rc 0: phase2 spilled off node P onto cpuset-allowed DRAM (PASS).
	# rc 1: landed on P (bind not dropped); rc 2: SIGBUS (no fallback); 135: killed.
	case "$rc" in
	0) ktap_test_pass "fault on node $PN dropped from cpuset spilled to allowed DRAM" ;;
	1) ktap_test_fail "fault still landed on forbidden node $PN" ;;
	2|135) ktap_test_fail "fault SIGBUS'd instead of spilling to allowed DRAM (rc=$rc)" ;;
	*) ktap_test_fail "unexpected rc=$rc" ;;
	esac
fi
echo $$ > "$CG/cgroup.procs" 2>/dev/null
rmdir "$g" 2>/dev/null

# 2. foreign cpuset: mems never includes P; mbind({P}) must not place on P
g="$CG/pn_foreign"
mkdir -p "$g" 2>/dev/null
echo "$CPUS" > "$g/cpuset.cpus" 2>/dev/null
echo "$DRAM" > "$g/cpuset.mems" 2>/dev/null
out=$( ( echo $BASHPID > "$g/cgroup.procs"; exec "$TOOL" mbind "$PN" 32 ) 2>&1 )
echo "$out" | sed 's/^/# /'
echo $$ > "$CG/cgroup.procs" 2>/dev/null
rmdir "$g" 2>/dev/null
placed=$(echo "$out" | sed -n "s/.*on_node$PN=\([0-9]*\).*/\1/p")
if [ "${placed:-0}" -gt 0 ] 2>/dev/null; then
	ktap_test_fail "$placed pages placed on private node $PN outside its cpuset"
else
	ktap_test_pass "mbind({$PN}) from a foreign cpuset placed nothing on node $PN"
fi

pn_reset
ktap_finished
