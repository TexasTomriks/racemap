// racemap: shared crypto state passed to an async request setter without a
// per-request snapshot taken under lock.
//
// Detects async crypto requests that pass shared IV state by pointer without a
// per-request snapshot taken under lock. This rule flags the unsnapshotted
// form and exonerates a form that copies the field into a per-request buffer
// under lock first.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
// which src/scanner/scanner.py parses into a Candidate.
//
// Run:  spatch --sp-file shared_iv_no_snapshot.cocci --dir <kernel>/crypto

virtual report

// ---- VULNERABLE: ctx->iv handed directly to the async setter --------------
@race exists@
identifier ctx;
expression req, src, dst, len;
position p;
@@
  skcipher_request_set_crypt@p(req, src, dst, len, ctx->iv)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:ctx->iv" % (p[0].file, p[0].line)
)

// ---- SAFE: a per-request snapshot of ctx->iv exists before the setter -----
// (documented as the negative pattern; suppressed from report output)
@safe exists@
identifier ctx;
expression req, src, dst, len, iv;
@@
  memcpy(iv, ctx->iv, ...);
  ... when != ctx->iv = ...
  skcipher_request_set_crypt(req, src, dst, len, iv)
