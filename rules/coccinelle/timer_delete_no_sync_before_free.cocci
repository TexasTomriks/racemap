// racemap: a struct field of type struct timer_list is torn down with the
// non-synchronizing timer_delete()/del_timer() (which only prevents the
// timer from firing AGAIN, it does NOT wait for a callback that is
// ALREADY running to finish), and the containing object is then freed
// shortly after in the same function, with no sync variant
// (timer_delete_sync()/del_timer_sync()) anywhere in between. An in-flight
// timer callback can still be executing -- and touching the object's
// memory -- when the free releases it back to the slab allocator
// (CWE-416 UAF).
//
// Unlike a generic "any kfree() with no mitigation nearby" rule (which
// would flood on every free in the kernel), this one requires seeing the
// actual non-sync timer_delete()/del_timer() call as a positive trigger --
// that call is rare and deliberate, so no per-struct type constraint is
// needed to stay precise; this is safe to run tree-wide, unlike
// toctou_double_fetch (see that rule's own tree-wide-flood warning).
//
// Real-world precedent: CVE-2026-23281, "wifi: libertas: fix use-after-free
// in lbs_free_adapter()" -- command_timer/tx_lockup_timer were torn down
// with the non-sync del_timer(), before the fix moved to
// timer_delete_sync(). (That specific historical instance split the timer
// teardown and the actual kfree() across two functions, so it doesn't
// itself match this same-function rule -- see queuemap's
// timer_delete_without_sync_free.json for the fuller writeup. This rule
// targets the more common single-function variant of the same bug class.)
//
// Detects: `timer_delete(&X->F);` (or del_timer, same shape) ... later ...
// `kfree(X);` in the same function, with no timer_delete_sync()/
// del_timer_sync() on the same field in between.
// Exonerates: the sync variant used instead, or used to additionally
// cancel the timer before the free.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file timer_delete_no_sync_before_free.cocci -D report --dir <kernel>

virtual report

@race exists@
identifier func;
expression obj;
identifier tfield;
position p;
@@
  func(...)
  {
  ...
(
  timer_delete(&obj->tfield);
|
  del_timer(&obj->tfield);
)
  ... when != timer_delete_sync(&obj->tfield)
      when != del_timer_sync(&obj->tfield)
  kfree@p(obj);
  ...
  }

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:timer_no_sync" % (p[0].file, p[0].line)
)

@safe exists@
identifier func;
expression obj;
identifier tfield;
@@
  func(...)
  {
  ...
(
  timer_delete_sync(&obj->tfield);
|
  del_timer_sync(&obj->tfield);
)
  ... when any
  kfree(obj);
  ...
  }
