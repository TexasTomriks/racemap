/*
 * Ground-truth fixture: CVE-2026-46324 (netfilter/nf_tables, netlink hook
 * unregistration), reduced to the literal inlined form (the real bug
 * routed the call_rcu() through a small helper function -- see
 * rules/coccinelle/list_del_before_call_rcu.cocci's LIMITATION note). Not
 * a working exploit.
 */
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

struct nft_hook {
	struct list_head list;
	struct rcu_head rcu;
};

static void __nft_hook_free_rcu(struct rcu_head *rcu)
{
	struct nft_hook *hook = container_of(rcu, struct nft_hook, rcu);

	kfree(hook);
}

static void nft_netdev_unregister_hooks(struct list_head *hook_list)
{
	struct nft_hook *hook, *next;

	list_for_each_entry_safe(hook, next, hook_list, list) {
#ifndef FIXED
		/* VULNERABLE: plain list_del() -- a concurrent netlink
		 * dumper walking this list under rcu_read_lock() can be
		 * mid-traversal through this exact node and dereference
		 * the LIST_POISON values list_del() writes. */
		list_del(&hook->list);
		call_rcu(&hook->rcu, __nft_hook_free_rcu);
#else
		/* FIXED: RCU-safe removal preserves the node's forward
		 * pointer for any in-flight reader. */
		list_del_rcu(&hook->list);
		call_rcu(&hook->rcu, __nft_hook_free_rcu);
#endif
	}
}
