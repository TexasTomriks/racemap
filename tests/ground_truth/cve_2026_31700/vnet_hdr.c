/*
 * Ground-truth fixture: CVE-2026-31700, "net/packet: fix TOCTOU race on
 * mmap'd vnet_hdr in tpacket_snd()".
 *
 * Root cause: with PACKET_VNET_HDR enabled, vnet_hdr pointed directly into
 * the mmap'd TX ring buffer shared with userspace. The kernel validated it
 * via __packet_snd_vnet_parse() and then re-read all fields later in
 * virtio_net_hdr_to_skb() -- a concurrent userspace thread could modify the
 * fields between validation and use, bypassing every safety check. The fix
 * copies vnet_hdr into a stack-local struct virtio_net_hdr before validation
 * and use, matching every other caller of virtio_net_hdr_to_skb() in the
 * tree (tun.c, tap.c, virtio_net.c), which already used stack copies --
 * tpacket_snd() was the one holdout.
 *
 * racemap must flag the vulnerable variant as likely_race and exonerate the
 * snapshotted variant. Synthetic test input -- not a working exploit.
 */
#include <linux/virtio_net.h>
#include <linux/skbuff.h>
#include <linux/string.h>

static int __packet_snd_vnet_parse(struct virtio_net_hdr *vnet_hdr, unsigned int len);

static int tpacket_snd(struct sk_buff *skb, void *data, int vio_le)
{
	int tp_len = 0;

#ifndef FIXED
	struct virtio_net_hdr *vnet_hdr = NULL;

	/* VULNERABLE: vnet_hdr still points into the shared mmap'd ring; a
	 * concurrent userspace write can change it between validation and use. */
	vnet_hdr = data;
	if (__packet_snd_vnet_parse(vnet_hdr, tp_len))
		return -EINVAL;

	if (virtio_net_hdr_to_skb(skb, vnet_hdr, vio_le))
		return -EINVAL;
#else
	struct virtio_net_hdr vnet_hdr;

	/* FIXED: snapshot into a stack-local before validation and use. */
	memcpy(&vnet_hdr, data, sizeof(vnet_hdr));
	if (__packet_snd_vnet_parse(&vnet_hdr, tp_len))
		return -EINVAL;

	if (virtio_net_hdr_to_skb(skb, &vnet_hdr, vio_le))
		return -EINVAL;
#endif

	return 0;
}
