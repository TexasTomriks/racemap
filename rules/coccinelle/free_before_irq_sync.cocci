// racemap: a function frees a resource (kfree()) BEFORE it calls
// free_irq()/devm_free_irq() later in the same function -- an ordering
// violation, not just an absent mitigation. free_irq()/devm_free_irq()
// uniquely both unregister an interrupt handler AND synchronize with any
// in-flight invocation (via synchronize_irq()) in one call; calling it
// AFTER a resource the ISR might touch has already been freed defeats
// that synchronization entirely -- an interrupt that fires in the window
// between the free and the (too-late) free_irq() can dereference freed
// memory (CWE-416 UAF).
//
// This requires BOTH calls to be present, in the wrong order, as a
// positive trigger -- not just "kfree() with no free_irq() nearby" (which
// would flood, like toctou_double_fetch, since most kfree() calls have
// nothing to do with an IRQ at all). A function that calls free_irq() at
// all has already shown clear intent to synchronize with its ISR; getting
// the order wrong relative to another free in the SAME function is a
// specific, plausible mistake worth flagging tree-wide.
//
// Real-world precedent: CVE-2026-43426, "usb: renesas_usbhs: fix
// use-after-free in ISR during device removal" -- usbhs_remove() froze
// pipe resources via usbhs_pipe_remove() before devm_free_irq() (that
// specific instance is object/tear-down-helper shaped rather than a bare
// kfree(); this rule generalizes to the more literal
// kfree()-before-free_irq() variant of the same ordering mistake).
//
// TREE-WIDE REVIEW (2026-08-24): 45 hits on a full-tree sweep. The
// dominant false-positive class is LOOP-ITERATION CONFLATION: Coccinelle's
// "..." is flow-insensitive about loop boundaries, so a kfree() in one
// loop iteration/branch can get paired with an unrelated free_irq() call
// from a DIFFERENT iteration or error-unwind label in the same function
// (e.g. drivers/vfio/platform/vfio_platform_irq.c's per-index cleanup
// loop) even though the real per-iteration order is correct. The second
// false-positive class is simply an unrelated free: kfree(X) and the
// free_irq()'s dev-arg not actually being the same object/data the ISR
// touches (this rule has no cross-reference for that -- see
// drivers/misc/cardreader/rtsx_pcr.c:1582 for a concrete instance, whose
// investigation also surfaced a separate observation in the same file: a
// probe()-failure path there frees pcr->slots without
// cancel_delayed_work_sync(&pcr->carddet_work), which free_irq() alone
// does not protect against. Assessed as a robustness issue, not
// security-relevant -- reachable only via an OOM/hardware failure during
// probe, with no attacker-controlled trigger path -- so not reported
// upstream). Every hit still needs manual verification of what the ISR
// actually dereferences.
//
// Detects: kfree(X); ... free_irq(...)|devm_free_irq(...); in one function.
// Exonerates: free_irq()/devm_free_irq() called before the kfree().
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file free_before_irq_sync.cocci -D report --dir <kernel>

virtual report

@race exists@
identifier func;
expression obj;
position p;
@@
  func(...)
  {
  ...
  kfree@p(obj);
  ...
(
  free_irq(...);
|
  devm_free_irq(...);
)
  ...
  }

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:free_before_irq_sync" % (p[0].file, p[0].line)
)

@safe exists@
identifier func;
expression obj;
@@
  func(...)
  {
  ...
(
  free_irq(...);
|
  devm_free_irq(...);
)
  ...
  kfree(obj);
  ...
  }
