// racemap: a raw pointer into shared/mmap'd memory passed directly into
// virtio_net_hdr_to_skb() instead of a per-call stack snapshot.
//
// Ground truth: CVE-2026-31700, "net/packet: fix TOCTOU race on mmap'd
// vnet_hdr in tpacket_snd()" — with PACKET_VNET_HDR enabled, vnet_hdr
// pointed directly into the mmap'd TX ring buffer shared with userspace.
// The kernel validated it via __packet_snd_vnet_parse() and then re-read
// all fields later in virtio_net_hdr_to_skb() — a concurrent userspace
// thread could modify the fields between validation and use, bypassing
// every safety check. Fixed by copying vnet_hdr into a stack-local
// `struct virtio_net_hdr` before validation and use, matching every other
// caller of virtio_net_hdr_to_skb() in the tree (tun.c, tap.c, virtio_net.c),
// which already used stack copies — tpacket_snd() was the one holdout.
//
// Detects: virtio_net_hdr_to_skb(skb, ptr, flags) where the header arg is a
// bare pointer variable (not the address of a stack local).
// Exonerates: virtio_net_hdr_to_skb(skb, &local, flags) — address-of a
// local/stack variable, i.e. a snapshot rather than a live shared pointer.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file vnet_hdr_no_snapshot.cocci -D report --dir <kernel>/net

virtual report

@race exists@
expression skb, vle;
identifier hdr;
position p;
@@
  virtio_net_hdr_to_skb@p(skb, hdr, vle)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:vnet_hdr" % (p[0].file, p[0].line)
)

// ---- SAFE: &local (a stack-snapshot), not a live shared pointer -----------
@safe exists@
expression skb, vle;
identifier hdr;
@@
  virtio_net_hdr_to_skb(skb, &hdr, vle)
