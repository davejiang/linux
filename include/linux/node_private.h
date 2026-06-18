/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NODE_PRIVATE_H
#define _LINUX_NODE_PRIVATE_H

#include <linux/mm.h>
#include <linux/nodemask.h>

struct page;

/*
 * Per-node service opt-ins (node_private.caps).  A private node is isolated
 * from all general mm services by default; the registering driver sets these
 * to let specific services operate on its node.
 */
#define NODE_PRIVATE_CAP_RECLAIM	(1UL << 0)	/* allow mm reclaim */
#define NODE_PRIVATE_CAP_MEMPOLICY		(1UL << 1)	/* allow userspace mbind()/set_mempolicy() */
#define NODE_PRIVATE_CAP_HOTUNPLUG	(1UL << 2)	/* allow hot-unplug via migration */
#define NODE_PRIVATE_CAP_TIERING	(1UL << 3)	/* allow kernel tiering migration (demotion/NUMA balancing/DAMON) */
#define NODE_PRIVATE_CAP_LTPIN		(1UL << 4)	/* allow longterm GUP pin */
#define NODE_PRIVATE_CAP_USER_MIGRATE	(1UL << 5)	/* allow userspace move_pages() to/from the node */

/**
 * struct node_private - Per-node container for N_MEMORY_PRIVATE nodes
 *
 * Allocated by the driver and passed to node_private_register().
 * The driver owns the memory and must ensure it remains valid until after
 * node_private_unregister() returns.
 *
 * @owner: Opaque driver identifier
 * @caps: NODE_PRIVATE_CAP_* service opt-ins for the node (zero by default;
 *	  individual capabilities are defined and consumed by later changes)
 */
struct node_private {
	void *owner;
	unsigned long caps;
};

/*
 * Which mm operation wants to reach a target node, and thus which per-node
 * capability authorises reaching a private (N_MEMORY_PRIVATE) node for it.
 * Used by alloc_zonelist_for_node() so the private zonelist cannot be selected
 * without naming the operation whose capability allows it.
 */
enum node_alloc_reason {
	NODE_ALLOC_RECLAIM,		/* reclaim / compaction / khugepaged collapse */
	NODE_ALLOC_TIERING,		/* demotion / kernel tiering migration */
	NODE_ALLOC_USER_MIGRATE,	/* move_pages() */
};

#ifdef CONFIG_NUMA
#include <linux/mmzone.h>

static inline bool folio_is_private_node(struct folio *folio)
{
	return node_state(folio_nid(folio), N_MEMORY_PRIVATE);
}

static inline bool page_is_private_node(struct page *page)
{
	return node_state(page_to_nid(page), N_MEMORY_PRIVATE);
}

/**
 * node_allows_reclaim - may the mm reclaim from this node?
 * @nid: the node to test
 *
 * Only a private node is ever excluded.  Every other node can safely
 * be operated on by reclaim.
 */
static inline bool node_allows_reclaim(int nid)
{
	struct node_private *np;
	bool ret;

	if (!node_state(nid, N_MEMORY_PRIVATE))
		return true;
	rcu_read_lock();
	np = rcu_dereference(NODE_DATA(nid)->node_private);
	ret = np && (np->caps & NODE_PRIVATE_CAP_RECLAIM);
	rcu_read_unlock();
	return ret;
}

/**
 * node_allows_mempolicy - may userspace place memory here via mempolicy?
 * @nid: the node to test
 *
 * Governs mbind()/set_mempolicy()/home_node placement onto a private node.
 * True for normal nodes and private nodes opted into CAP_MEMPOLICY.
 */
static inline bool node_allows_mempolicy(int nid)
{
	struct node_private *np;
	bool ret;

	if (!node_state(nid, N_MEMORY_PRIVATE))
		return true;
	rcu_read_lock();
	np = rcu_dereference(NODE_DATA(nid)->node_private);
	ret = np && (np->caps & NODE_PRIVATE_CAP_MEMPOLICY);
	rcu_read_unlock();
	return ret;
}

/**
 * node_allows_hotunplug - may hot-unplug migrate this node's folios?
 * @nid: the node to test
 *
 * True for normal nodes and private nodes opted into CAP_HOTUNPLUG.
 */
static inline bool node_allows_hotunplug(int nid)
{
	struct node_private *np;
	bool ret;

	if (!node_state(nid, N_MEMORY_PRIVATE))
		return true;
	rcu_read_lock();
	np = rcu_dereference(NODE_DATA(nid)->node_private);
	ret = np && (np->caps & NODE_PRIVATE_CAP_HOTUNPLUG);
	rcu_read_unlock();
	return ret;
}

/**
 * node_allows_tiering - may kernel tiering migrate to/scan this node?
 * @nid: the node to test
 *
 * Governs the kernel's access-aware migration subsystems on a private node:
 * demotion (as a target), NUMA balancing, and DAMON migration.
 * True for normal nodes and private nodes opted into CAP_TIERING.
 */
static inline bool node_allows_tiering(int nid)
{
	struct node_private *np;
	bool ret;

	if (!node_state(nid, N_MEMORY_PRIVATE))
		return true;
	rcu_read_lock();
	np = rcu_dereference(NODE_DATA(nid)->node_private);
	ret = np && (np->caps & NODE_PRIVATE_CAP_TIERING);
	rcu_read_unlock();
	return ret;
}

/**
 * node_allows_ltpin - may a folio on this node be long-term GUP-pinned?
 * @nid: the node to test
 *
 * Opted-out private nodes cause longterm pins to outright fail regardless
 * of ZONE placement (NORMAL would allow, MOVABLE would migrate first).
 *
 * Opted-in private nodes allow longterm pins to operate normally.
 */
static inline bool node_allows_ltpin(int nid)
{
	struct node_private *np;
	bool ret;

	if (!node_state(nid, N_MEMORY_PRIVATE))
		return true;
	rcu_read_lock();
	np = rcu_dereference(NODE_DATA(nid)->node_private);
	ret = np && (np->caps & NODE_PRIVATE_CAP_LTPIN);
	rcu_read_unlock();
	return ret;
}

/**
 * node_allows_user_migrate - may userspace move_pages() to/from this node?
 * @nid: the node to test
 *
 * Gates explicit userland migration (move_pages()) in both directions.  A
 * complete placement-target predicate: true for an N_MEMORY node or a private
 * node opted into CAP_USER_MIGRATE; false for an offline/memoryless node or a
 * non-opted private node.  The N_MEMORY early-out also keeps the NODE_DATA deref
 * to online private nodes, whose node_private pointer is valid.
 */
static inline bool node_allows_user_migrate(int nid)
{
	struct node_private *np;
	bool ret;

	if (node_state(nid, N_MEMORY))
		return true;
	if (!node_state(nid, N_MEMORY_PRIVATE))
		return false;
	rcu_read_lock();
	np = rcu_dereference(NODE_DATA(nid)->node_private);
	ret = np && (np->caps & NODE_PRIVATE_CAP_USER_MIGRATE);
	rcu_read_unlock();
	return ret;
}

/**
 * alloc_zonelist_for_node - the zonelist a targeted allocation uses to reach @nid
 * @nid: the intended target node
 * @reason: the mm operation requesting the allocation
 *
 * Returns ALLOC_ZONELIST_PRIVATE only for a private (N_MEMORY_PRIVATE) node that
 * opted into the capability @reason needs; otherwise ALLOC_ZONELIST_DEFAULT,
 * whose zonelist excludes private zones.  This is the single cap-enforcing point
 * for targeted allocators (collapse, demotion, move_pages): the private zonelist
 * cannot be selected without naming the operation whose capability authorises
 * it, so no path can silently reach a private node it is not allowed to.  It
 * does NOT replace a caller's own gate where that gate has distinct failure
 * semantics (e.g. move_pages returning -ENODEV); it is the allocation backstop.
 */
static inline enum alloc_zonelist
alloc_zonelist_for_node(int nid, enum node_alloc_reason reason)
{
	bool ok;

	if (!node_state(nid, N_MEMORY_PRIVATE))
		return ALLOC_ZONELIST_DEFAULT;
	switch (reason) {
	case NODE_ALLOC_RECLAIM:
		ok = node_allows_reclaim(nid);
		break;
	case NODE_ALLOC_TIERING:
		ok = node_allows_tiering(nid);
		break;
	case NODE_ALLOC_USER_MIGRATE:
		ok = node_allows_user_migrate(nid);
		break;
	default:
		ok = false;
	}
	return ok ? ALLOC_ZONELIST_PRIVATE : ALLOC_ZONELIST_DEFAULT;
}

/**
 * alloc_zonelist_for_nodemask - as alloc_zonelist_for_node() but for a target
 * nodemask (e.g. a migration-target set): ALLOC_ZONELIST_PRIVATE if any node in
 * @nmask is a private node authorised for @reason.
 */
static inline enum alloc_zonelist
alloc_zonelist_for_nodemask(const nodemask_t *nmask, enum node_alloc_reason reason)
{
	int nid;

	if (!nmask)
		return ALLOC_ZONELIST_DEFAULT;
	for_each_node_mask(nid, *nmask)
		if (alloc_zonelist_for_node(nid, reason) == ALLOC_ZONELIST_PRIVATE)
			return ALLOC_ZONELIST_PRIVATE;
	return ALLOC_ZONELIST_DEFAULT;
}

#else /* !CONFIG_NUMA */

static inline bool folio_is_private_node(struct folio *folio)
{
	return false;
}

static inline bool page_is_private_node(struct page *page)
{
	return false;
}

static inline bool node_allows_reclaim(int nid)
{
	return true;
}

static inline bool node_allows_mempolicy(int nid)
{
	return true;
}

static inline bool node_allows_hotunplug(int nid)
{
	return true;
}

static inline bool node_allows_tiering(int nid)
{
	return true;
}

static inline bool node_allows_ltpin(int nid)
{
	return true;
}

static inline bool node_allows_user_migrate(int nid)
{
	return true;
}

static inline enum alloc_zonelist
alloc_zonelist_for_node(int nid, enum node_alloc_reason reason)
{
	return ALLOC_ZONELIST_DEFAULT;
}

static inline enum alloc_zonelist
alloc_zonelist_for_nodemask(const nodemask_t *nmask, enum node_alloc_reason reason)
{
	return ALLOC_ZONELIST_DEFAULT;
}

#endif /* CONFIG_NUMA */

#if defined(CONFIG_NUMA) && defined(CONFIG_MEMORY_HOTPLUG)

int node_private_register(int nid, struct node_private *np);
int node_private_unregister(int nid);

#else /* !CONFIG_NUMA || !CONFIG_MEMORY_HOTPLUG */

static inline int node_private_register(int nid, struct node_private *np)
{
	return -ENODEV;
}

static inline int node_private_unregister(int nid)
{
	return 0;
}

#endif /* CONFIG_NUMA && CONFIG_MEMORY_HOTPLUG */

#endif /* _LINUX_NODE_PRIVATE_H */
