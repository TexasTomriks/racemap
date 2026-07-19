/*
 * Ground-truth fixture: CVE-2026-43284 (Dirty Frag), ESP in-place-decryption
 * shared-fragment bug, expressed against the equivalent TIPC code path.
 *
 * Root cause: an AEAD decrypt issued in place (src == dst) over an skb whose
 * page fragments may still be shared lets a concurrent writer mutate the
 * ciphertext while the crypto operation is in flight. skb_cow_data() alone is
 * not sufficient: it copies the linear/paged data but does not establish that
 * the fragments are unshared for the duration of the operation. The ESP fix
 * added an explicit skb_has_shared_frag() check before the in-place path.
 *
 * racemap must flag the vulnerable variant as likely_race and exonerate the
 * guarded variant. Synthetic test input -- not a working exploit.
 */
#include <crypto/aead.h>
#include <linux/skbuff.h>

static int tipc_aead_decrypt(struct net *net, struct tipc_aead *aead,
			     struct sk_buff *skb)
{
	struct aead_request *req;
	struct scatterlist *sg;
	int nsg, unused, err;

	nsg = skb_cow_data(skb, 0, &unused);
	if (nsg < 0)
		return nsg;

#ifndef FIXED
	/* VULNERABLE: in-place decrypt (src == dst) with no shared-fragment
	 * guard; a concurrent writer can mutate the buffer mid-operation. */
	aead_request_set_crypt(req, sg, sg, skb->len, req->iv);
#else
	/* FIXED: refuse the in-place fast path while fragments are still
	 * shared, as the ESP fix does, so the operation runs over memory this
	 * skb exclusively owns. */
	if (skb_has_shared_frag(skb)) {
		err = skb_linearize(skb);
		if (err)
			return err;
	}
	aead_request_set_crypt(req, sg, sg, skb->len, req->iv);
#endif

	return crypto_aead_decrypt(req);
}
