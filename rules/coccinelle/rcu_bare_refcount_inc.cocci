// racemap: an RCU-protected list/hlist walk finds a matching object and
// takes a reference with a BARE refcount_inc() before returning it,
// instead of refcount_inc_not_zero(). Under RCU, the walk only
// guarantees the object's *memory* stays valid until the read-side
// critical section ends (via kfree_rcu()/call_rcu()) -- it does NOT
// guarantee the object's refcount hasn't already dropped to zero on
// another CPU (the final put -> free race). A bare refcount_inc() on an
// already-zero counter resurrects a soon-to-be (or already scheduled to
// be) freed object; the caller gets back a pointer whose backing memory
// is freed once the RCU grace period closes, and any subsequent
// dereference is a slab use-after-free (CWE-416).
//
// Ground truth: CVE-2026-63918, "l2tp: use refcount_inc_not_zero in
// l2tp_session_get_by_ifname" -- every OTHER session getter in
// net/l2tp/l2tp_core.c already used refcount_inc_not_zero() (continuing
// the walk on failure); this one getter was the sole bare-refcount_inc()
// outlier, reachable by a reader racing a concurrent
// refcount_dec_and_test() -> l2tp_session_free() -> kfree_rcu() on
// another CPU inside the same rcu_read_lock_bh() section.
//
// Detects: refcount_inc(&obj->field) inside a
// list_for_each_entry_rcu()/hlist_for_each_entry_rcu()/
// hlist_nulls_for_each_entry_rcu() loop, followed by `return obj;` with
// no not_zero check gating it. The nulls variant is included because it's
// the dominant idiom for networking hash tables (inet socket lookup
// tables etc.) -- exactly the kind of hot, heavily-refcounted RCU lookup
// path this bug class targets. Scoped to refcount_inc only (not
// atomic_inc) -- the real CVE and the kernel's own file-internal
// consistency convention (every other getter in the same file already
// used the _t refcount API) both point at refcount_t as the realistic
// target; a nested (refcount_inc|atomic_inc) statement disjunction inside
// the outer list/hlist disjunction also failed to parse on this
// Coccinelle build (1.1.1) -- another instance of the "nested disjunction
// fragility" gotcha, worked around by dropping the inner one rather than
// chasing the exact parser limitation.
// Exonerates: `if (!refcount_inc_not_zero(&obj->field)) continue;` gating
// the same return.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file rcu_bare_refcount_inc.cocci -D report --dir <kernel>/net

virtual report

@race exists@
iterator name list_for_each_entry_rcu;
iterator name hlist_for_each_entry_rcu;
iterator name hlist_nulls_for_each_entry_rcu;
identifier obj, fld, member, node;
expression head;
position p;
@@
(
list_for_each_entry_rcu(obj, head, member)
{
  ...
  refcount_inc@p(&obj->fld);
  ...
  return obj;
  ...
}
|
hlist_for_each_entry_rcu(obj, head, member)
{
  ...
  refcount_inc@p(&obj->fld);
  ...
  return obj;
  ...
}
|
hlist_nulls_for_each_entry_rcu(obj, node, head, member)
{
  ...
  refcount_inc@p(&obj->fld);
  ...
  return obj;
  ...
}
)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:rcu_bare_refcount_inc" % (p[0].file, p[0].line)
)

@safe exists@
iterator name list_for_each_entry_rcu;
iterator name hlist_for_each_entry_rcu;
iterator name hlist_nulls_for_each_entry_rcu;
identifier obj, fld, member, node;
expression head;
@@
(
list_for_each_entry_rcu(obj, head, member)
{
  ...
  if (!refcount_inc_not_zero(&obj->fld))
    continue;
  ...
  return obj;
  ...
}
|
hlist_for_each_entry_rcu(obj, head, member)
{
  ...
  if (!refcount_inc_not_zero(&obj->fld))
    continue;
  ...
  return obj;
  ...
}
|
hlist_nulls_for_each_entry_rcu(obj, node, head, member)
{
  ...
  if (!refcount_inc_not_zero(&obj->fld))
    continue;
  ...
  return obj;
  ...
}
)
