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
 *
 * v2 (2026-08-25): added the skb_to_sgvec() call that the real
 * tipc_aead_decrypt()/esp_input() always have before building `sg` -- the
 * rule now requires seeing it (to distinguish an skb-derived scatterlist
 * from an unrelated local/raw-pointer one; see inplace_decrypt_no_cow.cocci
 * for the tree-wide false-positive review that motivated this).
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

	sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
	if (!sg)
		return -ENOMEM;
	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, 0, skb->len);
	if (err < 0)
		return err;

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
