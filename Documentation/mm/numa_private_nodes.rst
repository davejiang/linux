.. SPDX-License-Identifier: GPL-2.0

====================
Private memory nodes
====================

A *private memory node* is a NUMA node whose memory is hotplugged by a driver
and deliberately hidden from the kernel's normal memory management.  Such a node
is marked ``N_MEMORY_PRIVATE`` instead of ``N_MEMORY``; the two states are
mutually exclusive, so a private node never appears in ``N_MEMORY`` and is never
considered by the page allocator's normal or fallback paths.

The intent is to give a driver a block of NUMA-addressable memory that the rest
of the kernel will not allocate from on its own, while still letting that memory
be mapped into processes as ordinary, struct-page, LRU-managed folios -- and to
let the driver re-enable individual mm services on the node one at a time.

Preconditions
=============

A private node must be **CPU-less**.  ``N_MEMORY_PRIVATE`` and ``N_MEMORY`` are
mutually exclusive, so the backing memory must come up on a node that has no
DRAM of its own (otherwise the node would already be ``N_MEMORY``).  In practice
the memory is provided by a dax device whose target node has no other memory.

Isolation model
===============

Isolation is *opt-in by exclusion* and is **structural**: by default nothing in
the kernel can place memory on a private node because the node is absent from the
zonelists an ordinary allocation walks.

Zonelist exclusion
    ``build_zonelists()`` omits private nodes from both the ``FALLBACK`` and the
    ``NOFALLBACK`` (``__GFP_THISNODE``) zonelists.  An ordinary allocation -- even
    one carrying ``__GFP_THISNODE``, and including slab and hugetlb allocations
    that go through the buddy allocator -- therefore can never select a private
    node, regardless of the allocating context.  Because the isolation is in the
    zonelist structure rather than in per-task state, it cannot be defeated by
    interrupt or reclaim/folio nesting inheriting a task flag.

    A separate ``ZONELIST_PRIVATE`` zonelist holds the full node order over
    ``N_MEMORY | N_MEMORY_PRIVATE`` -- the only list that contains private-node
    zones.  It is selected solely when ``ac->zlsel == ALLOC_ZONELIST_PRIVATE``
    (``enum alloc_zonelist`` in ``struct alloc_context``); the boundary entries
    ``__alloc_frozen_pages_zonelist()`` / ``__folio_alloc_zonelist()`` stamp it.
    When ``CONFIG_NUMA`` is disabled ``ZONELIST_PRIVATE`` aliases
    ``ZONELIST_FALLBACK`` and is never selected.  ``alloc_contig``, the one
    allocator that does not use a zonelist, keeps an explicit
    ``node_state(N_MEMORY_PRIVATE)`` guard.

The mempolicy path
    ``MPOL_F_PRIVATE`` is an internal mempolicy flag (never accepted from
    userspace) marking a bind onto a private node; ``mpol_set_nodemask()``
    stamps it when a requested private node survives trimming.
    ``alloc_pages_mpol()`` maps such a bind to ``ALLOC_ZONELIST_PRIVATE`` so the
    allocation uses ``ZONELIST_PRIVATE``.  It is an ordinary, relaxable
    ``MPOL_BIND``: an unsatisfiable request -- an unmovable allocation on a
    movable-only node, or a cpuset that excludes the node -- simply falls back.
    Access control is the single trim in ``mpol_set_nodemask()``: a private node
    is dropped from a userspace nodemask unless it is opted in via
    ``CAP_MEMPOLICY`` (``node_allows_mempolicy()``), so ``mbind()``,
    ``set_mempolicy()`` and the home node are gated uniformly with no
    per-syscall special-casing.  ``migrate_pages()`` rides on the same trim
    (its nodemask is trimmed identically).  mlock is *not* gated -- it only pins
    residency, which a private node already provides, so it always does the
    right thing.

Userland migration (move_pages)
    ``move_pages(2)`` is explicit, per-page relocation of *existing* pages
    (distinct from the mempolicy *policy* syscalls), gated by a separate
    ``CAP_USER_MIGRATE`` via ``node_allows_user_migrate()``.  A private-node
    folio may be migrated off only if its node is opted in, and a private node
    is a valid migration *target* only if opted in -- ``do_move_pages_to_node()``
    then routes the target allocation through ``ZONELIST_PRIVATE`` (dropping
    ``__GFP_THISNODE``) and confines it to the node so the page lands there.

Provisioning
============

A driver brings memory up as private with::

    add_private_memory_driver_managed(mgid, start, size, resource_name,
                                      mhp_flags, online_type, np)

which onlines the range and registers the driver-owned ``struct node_private``
(``np``) describing the node, including its capability bitmap (see below).  The
node leaves ``N_MEMORY_PRIVATE`` only when the last range is offlined.

.. kernel-doc:: mm/memory_hotplug.c
   :identifiers: add_private_memory_driver_managed

.. kernel-doc:: drivers/base/node.c
   :identifiers: node_private_register node_private_unregister

Capabilities (per-service opt-ins)
==================================

Because the default is "no mm service touches the node", each service a driver
wants back is requested explicitly through a capability bit in
``np->caps``.  The mm side checks the matching ``node_allows_*()`` /
``folio_allows_*()`` predicate before acting:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Capability
     - Re-enables
   * - ``NODE_PRIVATE_CAP_RECLAIM``
     - reclaim of the node's folios, by the mm and by userspace
       ``MADV_COLD`` / ``PAGEOUT`` / ``FREE`` (userland-driven reclaim)
   * - ``NODE_PRIVATE_CAP_MEMPOLICY``
     - userspace placement policy: ``mbind()`` / ``set_mempolicy()`` / home node
   * - ``NODE_PRIVATE_CAP_HOTUNPLUG``
     - hot-unplug via migration
   * - ``NODE_PRIVATE_CAP_TIERING``
     - kernel access-aware migration: demotion target, NUMA balancing, and
       DAMON migration (``damon_pa_migrate``)
   * - ``NODE_PRIVATE_CAP_LTPIN``
     - ``FOLL_LONGTERM`` GUP pins
   * - ``NODE_PRIVATE_CAP_USER_MIGRATE``
     - userspace ``move_pages()`` to/from the node

Each base "disallow" change makes the private node safe by default; the matching
capability relaxes exactly that one service, so a capability can be dropped
independently without re-introducing a leak.

Dependencies between capabilities are enforced **once**, by
``node_private_register()`` at hotplug, rather than by whatever sets the bits:

* ``TIERING`` requires ``RECLAIM`` (a tiering node accumulates migrated/demoted
  pages, so without reclaim as a safety valve it would just fill up).

An inconsistent capability set is therefore not rejected when it is assembled;
it fails when the node is hotplugged (``-EINVAL`` from registration).

Observability
=============

A private node is reported through:

* ``/sys/devices/system/node/has_private_memory`` -- the ``N_MEMORY_PRIVATE``
  nodemask (mutually exclusive with ``has_memory``);
* ``/proc/<pid>/numa_maps`` -- per-node residency includes private nodes;
* ``/proc/kcore`` -- private-node RAM appears in the kcore RAM map;
* memcg per-node statistics account private-node memory.

Testing
=======

The ``anondax`` driver (``drivers/dax/anon.c``) is a testbed: it onlines a dax
device's memory as a private node and maps it into a process as ordinary
anonymous memory, exposing the capabilities as per-device sysfs toggles (see
Documentation/ABI/testing/sysfs-bus-dax).  KTAP selftests live in
``tools/testing/selftests/dax/`` (``private_node_*``).
