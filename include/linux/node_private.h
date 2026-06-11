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
