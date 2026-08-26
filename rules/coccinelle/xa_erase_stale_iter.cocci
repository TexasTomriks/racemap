// racemap: an xa_for_each() loop calls xa_erase() but discards its return
// value, then passes the LOOP ITERATOR variable (not the value xa_erase()
// itself removed) to a cleanup/put function. xa_erase() is atomic and
// returns the entry it actually removed (or NULL if a concurrent context
// already removed it first) -- discarding that return and using the
// stale iterated pointer instead means two concurrent contexts that both
// observe the same entry via xa_for_each() (before either erases it) can
// BOTH proceed to call the put function on it, even though only one of
// them "really" removed it from the array. If the put function drops the
// entry's last reference, this double-puts a single reference -- CWE-416
// (the entry can be freed while still mapped/referenced elsewhere).
//
// Ground truth: CVE-2026-46316, "KVM: arm64: vgic-its: Drop the
// translation cache reference only for the erased entry" --
// vgic_its_invalidate_cache() is called from three contexts with no
// mutual exclusion between them (ITS command handlers under its_lock,
// the GITS_CTLR write path under cmd_lock, and the EnableLPIs-clearing
// path under neither); each xa_for_each() iteration did
// `xa_erase(&cache, idx); vgic_put_irq(kvm, irq);` using the iterated
// `irq`, not xa_erase()'s return, letting two concurrent drains double-
// put the same cache reference.
//
// Detects: xa_erase(xa, idx); ... put_fn(entry, ...); inside an
// xa_for_each(xa, idx, entry) loop, where entry is the untouched loop
// iterator (xa_erase()'s return value is discarded).
// Exonerates: entry = xa_erase(xa, idx); (the iterator variable
// reassigned to the actual removed value) before the put call.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file xa_erase_stale_iter.cocci -D report <specific-file-or-dir>

virtual report

@race exists@
iterator name xa_for_each;
expression xa, idx;
identifier entry;
identifier put_fn;
position p;
@@
  xa_for_each(xa, idx, entry)
  {
  ...
  xa_erase(xa, idx);
  ...
  put_fn@p(..., entry, ...);
  ...
  }

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:xa_erase_stale_iter" % (p[0].file, p[0].line)
)

@safe exists@
iterator name xa_for_each;
expression xa, idx;
identifier entry;
identifier put_fn;
@@
  xa_for_each(xa, idx, entry)
  {
  ...
  entry = xa_erase(xa, idx);
  ...
  put_fn(entry, ...);
  ...
  }
