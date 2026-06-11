/*
 * sample_kernel fixture: net/zerocopy_race.c
 * Pattern D — MSG_ZEROCOPY skb_shared write without skb_unshare().
 *
 * After skb_zerocopy() clones the frags into a shared skb, the code writes to
 * skb->data while the skb is still shared (refcount > 1). The fix calls
 * skb_unshare() (deep copy when shared) before mutating the buffer.
 */
#include <linux/skbuff.h>

static int zc_send_patch(struct sk_buff *skb, struct sk_buff *orig, gfp_t gfp)
{
	int err;

#ifndef FIXED
	/* VULNERABLE: mutate shared skb data without unsharing first. */
	err = skb_zerocopy(skb, orig, orig->len, 0);
	if (err)
		return err;
	skb->data[0] ^= 0x80;
	return 0;
#else
	/* FIXED: deep-copy if shared before writing. */
	err = skb_zerocopy(skb, orig, orig->len, 0);
	if (err)
		return err;
	skb = skb_unshare(skb, gfp);
	if (!skb)
		return -ENOMEM;
	skb->data[0] ^= 0x80;
	return 0;
#endif
}
