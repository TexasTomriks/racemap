// racemap: an object is unlinked from a list with plain list_del() and
// then freed via an RCU-deferred call_rcu() in the same function -- a
// mismatched pair. list_del() poisons the removed node's next/prev
// pointers (LIST_POISON1/2); a concurrent RCU reader (list_for_each_entry_
// rcu()/a netlink dumper walking the same list under rcu_read_lock())
// that is mid-traversal through this exact node when list_del() runs can
// dereference those poison values -- CWE-416/general memory-safety
// corruption. Deferring the actual reclaim via call_rcu() is a strong
// signal that concurrent RCU readers of this list are expected to exist;
// the removal step must then also be RCU-safe (list_del_rcu(), which
// preserves the node's forward pointer for in-flight readers), not just
// the free step.
//
// Ground truth: CVE-2026-46324, "netfilter: nf_tables: use list_del_rcu
// for netlink hooks" -- nft_netdev_unregister_hooks() and
// __nft_unregister_flowtable_net_hooks() called list_del() (not _rcu)
// immediately before a helper that itself called call_rcu() to free the
// hook, while netlink dumpers concurrently walk the same hook list under
// RCU. Fixed by routing every removal through a shared
// list_del_rcu()+call_rcu() helper.
//
// LIMITATION: this rule only catches the literal, inlined form (bare
// call_rcu() visible at the call site) -- the real CVE-2026-46324 bug
// routed the free through a small wrapper function
// (nft_netdev_hook_free_rcu()) that called call_rcu() internally, one
// level removed from the list_del() call site; this single-function rule
// cannot see through that indirection. Still useful for the more literal
// variant of the same mistake, and as a targeted (not blind tree-wide)
// check against a specific suspect removal path.
//
// Detects: list_del(&obj->lfield); ... call_rcu(&obj->rfield, ...); in
// one function, on the same obj.
// Exonerates: list_del_rcu(&obj->lfield) used instead of list_del().
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file list_del_before_call_rcu.cocci -D report <specific-file-or-dir>

virtual report

@race exists@
identifier func;
expression obj;
identifier lfield, rfield;
position p;
@@
  func(...)
  {
  ...
  list_del@p(&obj->lfield);
  ...
  call_rcu(&obj->rfield, ...);
  ...
  }

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:list_del_rcu" % (p[0].file, p[0].line)
)

@safe exists@
identifier func;
expression obj;
identifier lfield, rfield;
@@
  func(...)
  {
  ...
  list_del_rcu(&obj->lfield);
  ...
  call_rcu(&obj->rfield, ...);
  ...
  }
