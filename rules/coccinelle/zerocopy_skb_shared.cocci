// racemap Pattern D — MSG_ZEROCOPY: skb mutated after skb_zerocopy() without
// skb_unshare() (shared skb data written while refcount > 1).
//
// Output: // RACEMAP:<file>:<line>:skb_shared_info
// Run: spatch --sp-file zerocopy_skb_shared.cocci --dir <kernel>/net

virtual report

@race exists@
expression skb, orig, len, hlen;
position p;
@@
  skb_zerocopy@p(skb, orig, len, hlen)
  ... when != skb_unshare(skb, ...)
      when != skb_copy(skb, ...)
  skb->data
  
@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(p[0], "RACEMAP:%s:%s:skb_shared_info" % (p[0].file, p[0].line))
