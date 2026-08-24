/*
 * Ground-truth fixture: CVE-2026-63918, "l2tp: use refcount_inc_not_zero
 * in l2tp_session_get_by_ifname" -- reduced from the real upstream
 * function (net/l2tp/l2tp_core.c). See rules/coccinelle/
 * rcu_bare_refcount_inc.cocci for the commit reference. Not a working
 * exploit.
 */
#include <linux/refcount.h>
#include <linux/list.h>
#include <linux/rcupdate.h>

struct l2tp_session {
	struct list_head list;
	refcount_t ref_count;
	char ifname[16];
};

static struct l2tp_session *
l2tp_session_get_by_ifname(struct list_head *session_list, const char *ifname)
{
	struct l2tp_session *session;

	rcu_read_lock_bh();
	list_for_each_entry_rcu(session, session_list, list) {
#ifndef FIXED
		if (!strcmp(session->ifname, ifname)) {
			/* VULNERABLE: bare refcount_inc() -- a concurrent
			 * refcount_dec_and_test() -> l2tp_session_free() on
			 * another CPU can drop this to zero between the
			 * strcmp() and the inc, resurrecting a
			 * soon-to-be-freed session. */
			refcount_inc(&session->ref_count);
			rcu_read_unlock_bh();
			return session;
		}
#else
		if (strcmp(session->ifname, ifname))
			continue;
		if (!refcount_inc_not_zero(&session->ref_count))
			continue;
		rcu_read_unlock_bh();
		return session;
#endif
	}
	rcu_read_unlock_bh();
	return NULL;
}
