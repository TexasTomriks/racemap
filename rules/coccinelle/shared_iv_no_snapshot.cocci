// racemap: shared crypto state passed to an async request setter without a
// per-request snapshot taken under lock.
//
// Detects async crypto requests that pass shared IV state by pointer without a
// per-request snapshot taken under lock. This rule flags the unsnapshotted
// form and exonerates a form that copies the field into a per-request buffer
// under lock first.
//
// v2 (2026-08-24): excludes the request object's own `->iv` field
// (`req->iv`, `areq->iv`, etc.) forwarded into a fallback/sub-request — this
// is a caller-owned, per-operation field with no concurrent-mutation path,
// unlike the vulnerable shape this rule targets (a persistent, externally-
// mutable-via-a-second-syscall context field like algif_skcipher's
// `ctx->iv`). Without this exclusion the rule fired on ~70 safe
// `skcipher_request_set_crypt(subreq, ..., req->iv)` sites across
// drivers/crypto/* and arch/*/crypto/* during a tree-wide scan — every one
// checked was the same safe forwarding idiom, not a real race. The excluded
// identifier list covers the request-parameter names actually seen in that
// sweep (req, areq) plus common sibling conventions in the same codebase
// (subreq, dreq, oreq) as a defensive margin; extend this list if a future
// scan turns up another safe-but-flagged naming convention.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
// which src/scanner/scanner.py parses into a Candidate.
//
// Run:  spatch --sp-file shared_iv_no_snapshot.cocci --dir <kernel>/crypto

virtual report

// ---- VULNERABLE: ctx->iv handed directly to the async setter --------------
@race exists@
identifier ctx != {req, areq, subreq, dreq, oreq};
expression req2, src, dst, len;
position p;
@@
  skcipher_request_set_crypt@p(req2, src, dst, len, ctx->iv)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:ctx->iv" % (p[0].file, p[0].line)
)

// ---- SAFE: a per-request snapshot of ctx->iv exists before the setter -----
// (documented as the negative pattern; suppressed from report output)
// NB: the metavariable must not be named `iv`, or Coccinelle reads the `iv` in
// `ctx->iv` as that metavariable in field position and fails to parse the rule.
@safe exists@
identifier ctx != {req, areq, subreq, dreq, oreq};
expression req2, src, dst, len, snap;
@@
  memcpy(snap, ctx->iv, ...);
  ... when != ctx->iv = ...
  skcipher_request_set_crypt(req2, src, dst, len, snap)
