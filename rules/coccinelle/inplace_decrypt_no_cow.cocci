// racemap: in-place AEAD decrypt without a shared-fragment / COW check.
//
// Secondary target (net/tipc/crypto.c, tipc_aead_decrypt): an in-place decrypt
// (src == dst) over an skb that may share page-cache fragments, missing the
// skb_has_shared_frag()/skb_cow_data() guard that ESP gained in CVE-2026-43284.
//
// Run:  spatch --sp-file inplace_decrypt_no_cow.cocci --dir <kernel>/net

virtual report

@inplace exists@
expression req, sg, len;
position p;
@@
  aead_request_set_crypt@p(req, sg, sg, len, ...)

@script:python depends on inplace && report@
p << inplace.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:skb(shared_frag)" % (p[0].file, p[0].line)
)
