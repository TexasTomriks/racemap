// racemap: in-place AEAD decrypt/encrypt over an skb-derived scatterlist
// (built via skb_to_sgvec()) without a shared-fragment / COW check
// (skb_cow_data()/skb_has_shared_frag()) first.
//
// Ground truth precedent: CVE-2026-43284 (ESP, net/ipv{4,6}/esp{4,6}.c) --
// an in-place decrypt (src == dst) over an skb whose fragment pages could
// be shared with another owner, missing the skb_cow_data()/
// skb_has_shared_frag() guard. Secondary target noted in the original
// version of this rule: net/tipc/crypto.c, tipc_aead_decrypt().
//
// TREE-WIDE REVIEW (2026-08-25): the v1 version of this rule had NO
// mitigation check at all -- it flagged every aead_request_set_crypt(req,
// sg, sg, len, ...) call unconditionally, producing 25 hits tree-wide,
// every single one a false positive on manual review. Two distinct false-
// positive classes drove this:
//  1. `sg` never actually built from an skb at all (e.g.
//     net/mac80211/aead_api.c's aead_encrypt()/aead_decrypt() are generic
//     helpers built from raw u8* pointers via sg_set_buf(), or
//     crypto/gcm.c's internal GHASH-key derivation uses a purely local,
//     synchronously-awaited kzalloc'd buffer) -- these have nothing to do
//     with shared/racy memory at all.
//  2. `sg` IS skb-derived (net/ipv{4,6}/esp{4,6}.c, drivers/net/macsec.c,
//     net/tipc/crypto.c all call skb_to_sgvec()) but the containing
//     function ALREADY has the CVE-2026-43284-style guard elsewhere (e.g.
//     esp4.c calls skb_has_shared_frag()/skb_cow_data() earlier in
//     esp_input()) -- v1 had no way to see that.
//
// v2 fixes both: requires `sg` to be built via skb_to_sgvec(skb, sg, ...)
// in the SAME function (excludes false-positive class 1 entirely), and
// adds a `when !=` exclusion for skb_has_shared_frag() on that same skb
// before the in-place crypt call (excludes false-positive class 2).
// Exclusion is on skb_has_shared_frag() ONLY, not skb_cow_data() -- per
// this rule's own ground truth (tests/ground_truth/cve_2026_43284/
// tipc_inplace.c), skb_cow_data() alone does not establish exclusive
// frag ownership for the CVE-2026-43284 bug class; only an explicit
// skb_has_shared_frag() check (or skb_linearize() gating on it, as the
// tipc fixture's FIXED branch does) is treated as sufficient.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file inplace_decrypt_no_cow.cocci -D report --dir <kernel>/net

virtual report

@race exists@
identifier func;
expression skb, sg, req, len, E1;
position p;
@@
  func(...)
  {
  ...
(
  skb_to_sgvec(skb, sg, ...);
|
  E1 = skb_to_sgvec(skb, sg, ...);
)
  ...
  when != skb_has_shared_frag(skb)
  aead_request_set_crypt@p(req, sg, sg, len, ...)
  ...
  }

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:skb(shared_frag)" % (p[0].file, p[0].line)
)

@safe exists@
identifier func;
expression skb, sg, req, len, E1;
@@
  func(...)
  {
  ...
(
  skb_to_sgvec(skb, sg, ...);
|
  E1 = skb_to_sgvec(skb, sg, ...);
)
  ...
  skb_has_shared_frag(skb);
  ... when any
  aead_request_set_crypt(req, sg, sg, len, ...)
  ...
  }
