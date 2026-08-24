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
// kfree(), see queuemap's usbhs_remove_irq_sync.json for that exact
// reduction; this rule generalizes to the more literal kfree()-before-
// free_irq() variant of the same ordering mistake).
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
