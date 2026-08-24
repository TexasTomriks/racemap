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
// TREE-WIDE REVIEW (2026-08-24): a full-tree sweep produced 11 matches;
// none were confirmed as real bugs after manual review. The dominant
// false-positive class is a caller-side lock the rule can't see: e.g.
// drivers/net/ethernet/chelsio/cxgb4/l2t.c's alloc_l2e() is documented
// "Must be called with l2t_data.lock held", and
// drivers/vfio/mdev/mdev_core.c has an explicit in-code comment
// ("non-atomic read and dec is fine here because all modifications are
// under mdev_list_lock") for the exact shape this rule flags. The zcrx
// ground-truth bug was real specifically BECAUSE it lacked such a lock;
// this rule has no way to check for one, so every hit still needs the
// same manual/LLM-triage pass a human would give any static match — lock-
// protection is a fundamentally different (and harder to automate)
// mitigation signal than "was there a nearby atomic_try_cmpxchg()". One
// hit (fs/smb/server/smb2pdu.c:9507, ksmbd's opinfo->breaking_cnt) looked
// plausibly racy on review but its impact, if real, is a plain counter
// going wrong rather than a double-free/UAF like zcrx's -- not pursued
// further; see POTENTIAL-FINDINGS.md.
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
