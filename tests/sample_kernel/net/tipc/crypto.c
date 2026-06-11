/*
 * sample_kernel fixture: net/tipc/crypto.c (reduced).
 * Contains ONE vulnerable pattern: in-place AEAD decrypt (src == dst) over an
 * skb that may share page-cache fragments, with NO skb_has_shared_frag() guard.
 *
 * This mirrors the gap relative to the ESP fix (CVE-2026-43284): ESP added a
 * shared-fragment check before in-place decrypt; TIPC has skb_cow_data() but no
 * equivalent skb_has_shared_frag() fast-path guard. See "tipc bug summart.txt".
 */
#include <crypto/aead.h>
#include <linux/skbuff.h>

static int tipc_aead_decrypt(struct net *net, struct tipc_aead *aead,
			     struct sk_buff *skb)
{
	struct aead_request *req;
	struct scatterlist *sg;
	int nsg, unused;

	/* COW the data but no skb_has_shared_frag() fast-path guard. */
	nsg = skb_cow_data(skb, 0, &unused);
	if (nsg < 0)
		return nsg;

	/* VULNERABLE: in-place decrypt (sg == sg) over possibly-shared frags. */
	aead_request_set_crypt(req, sg, sg, skb->len, req->iv);

	return crypto_aead_decrypt(req);
}
