// racemap: a shared atomic_t is checked via atomic_read() and, if nonzero,
// decremented via a SEPARATE atomic_dec() call — the check and the modify
// are two independent atomic operations, not one atomic read-modify-write,
// so a concurrent atomic_xchg()/atomic_try_cmpxchg() on the same counter
// between the read and the dec can race: both sides observe the pre-race
// value and both proceed, double-decrementing (or, for a refcount used to
// gate a freelist push, double-freeing) the underlying resource.
//
// Ground truth: CVE-2026-43121, "io_uring/zcrx: fix user_ref race between
// scrub and refill paths" — io_zcrx_put_niov_uref() used
// `if (!atomic_read(uref)) return false; atomic_dec(uref);`, racing
// io_zcrx_scrub()'s atomic_xchg() on the same counter without rq_lock. The
// race let the same niov get pushed onto a freelist twice (double-free),
// and further pushes performed an out-of-bounds u32 write past the
// kvmalloc'd freelist array into the adjacent slab object. Fixed by
// replacing the read-then-dec with an atomic_try_cmpxchg() loop — a single
// atomic compare-and-swap instead of two independent operations.
//
// Detects: `if (!atomic_read(X)) { ...; return ...; } ... atomic_dec(X);`
// with no atomic_try_cmpxchg()/atomic_cmpxchg() on X anywhere in between.
// Exonerates: the same shape where atomic_try_cmpxchg(X, ...) replaces the
// separate read+dec entirely.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file atomic_check_then_dec.cocci -D report --dir <kernel>/io_uring

virtual report

@race exists@
expression X;
position p;
@@
(
  if (!atomic_read(X))
  {
    ...
    return ...;
  }
|
  if (unlikely(!atomic_read(X)))
  {
    ...
    return ...;
  }
)
  ... when != atomic_try_cmpxchg(X, ...)
      when != atomic_cmpxchg(X, ...)
  atomic_dec@p(X);

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:atomic_t" % (p[0].file, p[0].line)
)

// ---- SAFE: a single atomic compare-and-swap instead of read-then-dec -----
@safe exists@
expression X;
@@
  atomic_try_cmpxchg(X, ...)
