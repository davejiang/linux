# SPDX-License-Identifier: GPL-2.0
#
# Shared provisioning and helpers for the private-node (anondax) selftests.
# Source after ktap_helpers.sh.  A private node is a CPU-less NUMA node onto
# which the anondax driver hotplugs dax memory as N_MEMORY_PRIVATE.
#
# Provisioning a dax device on a memoryless node needs daxctl/ndctl plus an
# emulated pmem region on a node with no DRAM, e.g. boot with:
#
#   memmap=1G!4G        (carves a >=1 memory-block pmem region; put it on a
#                        memoryless NUMA node via the platform's numa layout)
#
# then, in the booted system, a devdax namespace is created automatically by
# pn_provision().  If no suitable device can be found the caller SKIPs.

DAX_BASE=/sys/bus/dax/devices
NODE_BASE=/sys/devices/system/node

pn_require_root() {
	[ "$(id -u)" = 0 ] || { ktap_skip_all "must be run as root"; exit "$KSFT_SKIP"; }
}

# nodelist_has LIST NID -- true if NID is set in a nodelist string like "0,2-3".
nodelist_has() {
	local nid=$2 tok lo hi
	for tok in $(echo "$1" | tr ',' ' '); do
		lo=${tok%-*}; hi=${tok#*-}
		[ "$nid" -ge "$lo" ] 2>/dev/null && [ "$nid" -le "$hi" ] 2>/dev/null && return 0
	done
	return 1
}

# node_in_mask NID MASKFILE -- true if NID is set in $NODE_BASE/MASKFILE.
node_in_mask() {
	[ -r "$NODE_BASE/$2" ] && nodelist_has "$(cat "$NODE_BASE/$2")" "$1"
}

pn__find_bound() {	# echo a dax device already bound to anondax, if any
	local d drv
	for d in "$DAX_BASE"/dax*; do
		[ -e "$d/hotplug" ] || continue
		drv=$(readlink "$d/driver" 2>/dev/null)
		[ "$(basename "${drv:-}")" = anondax ] && { basename "$d"; return 0; }
	done
	return 1
}

pn__bind_one() {	# bind the first device_dax dax device on a memoryless node
	local d nid drv
	for d in "$DAX_BASE"/dax*; do
		[ -e "$d/target_node" ] || continue
		nid=$(cat "$d/target_node")
		[ "$nid" -ge 0 ] 2>/dev/null || continue
		node_in_mask "$nid" has_memory && continue	# need a memoryless node
		drv=$(readlink "$d/driver" 2>/dev/null)
		[ "$(basename "${drv:-}")" = device_dax ] &&
			echo "$(basename "$d")" > /sys/bus/dax/drivers/device_dax/unbind 2>/dev/null
		echo "$(basename "$d")" > /sys/bus/dax/drivers/anondax/new_id 2>/dev/null
		sleep 1
		return 0
	done
}

# pn_provision -- locate (or create+bind) an anondax dax device on a memoryless
# node.  On success sets DAX, D (its sysfs dir) and PN (its target node).
# SKIPs the whole test otherwise.
pn_provision() {
	modprobe -q nd_e820 dax_pmem device_dax nd_pmem 2>/dev/null
	modprobe -q anondax 2>/dev/null ||
		{ ktap_skip_all "anondax module unavailable (CONFIG_DEV_DAX_ANON=m)"; exit "$KSFT_SKIP"; }

	DAX=$(pn__find_bound)
	if [ -z "$DAX" ]; then
		# Reconfigure each pmem region's seed namespace to devdax mode; that
		# is what materialises the dax device(s) we can bind.
		if command -v ndctl >/dev/null 2>&1; then
			local r
			for r in $(ndctl list -R 2>/dev/null | grep -oE 'region[0-9]+'); do
				ndctl create-namespace -m devdax -e "${r/region/namespace}.0" -f \
					>/dev/null 2>&1
			done
		fi
		pn__bind_one
		DAX=$(pn__find_bound)
	fi
	[ -n "$DAX" ] ||
		{ ktap_skip_all "no anondax-bindable dax device on a memoryless node (see header for memmap= provisioning)"; exit "$KSFT_SKIP"; }

	D=$DAX_BASE/$DAX
	PN=$(cat "$D/target_node" 2>/dev/null)
	{ [ -n "$PN" ] && [ "$PN" -ge 0 ] 2>/dev/null; } ||
		{ ktap_skip_all "$DAX has no valid target_node"; exit "$KSFT_SKIP"; }
	{ [ -e "$D/hotplug" ] && [ -e "$D/reclaim" ]; } ||
		{ ktap_skip_all "$DAX missing anondax cap attributes"; exit "$KSFT_SKIP"; }
}

pn_set()     { echo "$2" > "$D/$1" 2>/dev/null; }	# pn_set ATTR VAL  (rc=write status)
pn_get()     { cat "$D/$1" 2>/dev/null; }
pn_hotplug() { echo "$1" > "$D/hotplug" 2>/dev/null; }	# pn_hotplug STATE (rc=status)
pn_state()   { cat "$D/hotplug" 2>/dev/null; }
pn_is_private() { node_in_mask "$PN" has_private_memory; }

# pn_reset -- best-effort return to an unplugged, all-caps-cleared baseline.
pn_reset() {
	pn_hotplug unplugged 2>/dev/null
	local c
	for c in ltpin tiering hotunplug mempolicy reclaim; do
		[ -e "$D/$c" ] && echo 0 > "$D/$c" 2>/dev/null
	done
}

# pn_provision_all -- bind EVERY device_dax device on a memoryless node to
# anondax (for the multi-private-node tests).  On success sets PN_DAXES and
# PN_NODES (space-separated, index-aligned).  Returns 0 always; the caller
# checks how many nodes were found and SKIPs if too few.
pn_provision_all() {
	modprobe -q nd_e820 dax_pmem device_dax nd_pmem 2>/dev/null
	modprobe -q anondax 2>/dev/null
	if command -v ndctl >/dev/null 2>&1; then
		local r
		for r in $(ndctl list -R 2>/dev/null | grep -oE 'region[0-9]+'); do
			ndctl create-namespace -m devdax -e "${r/region/namespace}.0" -f \
				>/dev/null 2>&1
		done
	fi
	local d nid drv
	PN_DAXES=; PN_NODES=
	for d in "$DAX_BASE"/dax*; do
		[ -e "$d/target_node" ] || continue
		nid=$(cat "$d/target_node"); [ "$nid" -ge 0 ] 2>/dev/null || continue
		node_in_mask "$nid" has_memory && continue	# memoryless only
		drv=$(basename "$(readlink "$d/driver" 2>/dev/null)" 2>/dev/null)
		[ "$drv" = device_dax ] &&
			echo "$(basename "$d")" > /sys/bus/dax/drivers/device_dax/unbind 2>/dev/null
		[ "$drv" = anondax ] ||
			echo "$(basename "$d")" > /sys/bus/dax/drivers/anondax/new_id 2>/dev/null
		PN_DAXES="$PN_DAXES $(basename "$d")"; PN_NODES="$PN_NODES $nid"
	done
	PN_DAXES=${PN_DAXES# }; PN_NODES=${PN_NODES# }
	sleep 1
}

# pn_swap_setup -- ensure at least one swap area is active.  Reuses an existing
# one, else swaps on the first unmounted block device (e.g. a vng --disk).
# Returns 0 on success; caller SKIPs on failure.  NEVER touches a mounted device.
pn_swap_setup() {
	[ "$(grep -c . /proc/swaps)" -gt 1 ] && return 0
	local d
	for d in /dev/vd? /dev/sd? /dev/nvme?n?; do
		[ -b "$d" ] || continue
		grep -q "^$d " /proc/mounts && continue		# in use as a fs
		swapon "$d" 2>/dev/null && return 0
		mkswap "$d" >/dev/null 2>&1 && swapon "$d" 2>/dev/null && return 0
	done
	return 1
}

# pn_cgroup2 -- echo a cgroup2 mount root with cpuset delegated to subtree
# control, or return 1 if cgroup2/cpuset is unavailable.
pn_cgroup2() {
	local root
	root=$(awk '$3=="cgroup2"{print $2; exit}' /proc/mounts)
	if [ -z "$root" ]; then
		root=/sys/fs/cgroup
		mkdir -p "$root" 2>/dev/null
		mount -t cgroup2 none "$root" 2>/dev/null
		root=$(awk '$3=="cgroup2"{print $2; exit}' /proc/mounts)
	fi
	[ -n "$root" ] || return 1
	grep -qw cpuset "$root/cgroup.controllers" 2>/dev/null || return 1
	grep -qw cpuset "$root/cgroup.subtree_control" 2>/dev/null ||
		echo "+cpuset" > "$root/cgroup.subtree_control" 2>/dev/null
	echo "$root"
}
