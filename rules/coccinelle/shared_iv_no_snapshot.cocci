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
// v3 (2026-08-25): a full-tree sweep after v2 still produced 10 hits; 9 of
// them (crypto/gcm.c, crypto/adiantum.c, crypto/chacha20poly1305.c,
// fs/ecryptfs/keystore.c) were a SECOND false-positive class the identifier
// exclusion didn't cover: `ctx` freshly kzalloc()'d INSIDE the same
// function that uses `ctx->iv`, then used entirely synchronously
// (crypto_wait_req() or equivalent) before the function returns -- a
// private, single-use local allocation, not the persistent, externally-
// mutable-via-a-second-syscall context this rule targets (algif_skcipher's
// `ctx` is looked up from the *socket*, allocated once at accept() time in
// a wholly different function, and remains live and reachable by a second
// concurrent syscall for as long as the socket exists). Added a `when !=
// ctx = <alloc_fn>(...)` exclusion: if the same function that uses
// `ctx->iv` also allocates `ctx` itself, the object cannot be the
// persistent shared kind. The one real hit (algif_skcipher.c:148) is
// unaffected -- its `ctx` comes from the socket's private data, never
// locally allocated in the vulnerable function.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
// which src/scanner/scanner.py parses into a Candidate.
//
// Run:  spatch --sp-file shared_iv_no_snapshot.cocci --dir <kernel>/crypto

virtual report

// ---- VULNERABLE: ctx->iv handed directly to the async setter --------------
@race exists@
identifier func;
identifier ctx != {req, areq, subreq, dreq, oreq};
expression req2, src, dst, len;
position p;
@@
  func(...)
  {
  ...
  when != ctx = kzalloc(...)
  when != ctx = kzalloc_obj(...)
  when != ctx = kmalloc(...)
  when != ctx = kmalloc_obj(...)
  when != ctx = kvzalloc(...)
  when != ctx = kvmalloc(...)
  skcipher_request_set_crypt@p(req2, src, dst, len, ctx->iv)
  ...
  }

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
