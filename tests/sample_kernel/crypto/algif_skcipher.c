/*
 * sample_kernel fixture: crypto/algif_skcipher.c (reduced).
 * Contains ONE vulnerable pattern and ONE clean (snapshotted) pattern.
 * Synthetic sample input modeled on a public kernel crypto path.
 */
#include <crypto/skcipher.h>

/* VULNERABLE: the shared IV state is passed by pointer, no per-request snapshot. */
static int _skcipher_recvmsg_vuln(struct sock *sk, struct af_alg_async_req *areq,
				  struct skcipher_ctx *ctx)
{
	skcipher_request_set_crypt(&areq->cra_u.skcipher_req,
				   areq->tsgl,
				   areq->first_rsgl.sgl.sgt.sgl,
				   areq->outlen, ctx->iv);

	return crypto_skcipher_decrypt(&areq->cra_u.skcipher_req);
}

/* CLEAN: the shared IV state is snapshotted into a per-request buffer under
 * lock first, so it is copied before the async handoff. racemap should triage
 * this likely_safe even though the sink matches. */
static int _skcipher_recvmsg_fixed(struct sock *sk, struct af_alg_async_req *areq,
				   struct skcipher_ctx *ctx, unsigned int ivsize)
{
	u8 *iv = skcipher_request_ctx(&areq->cra_u.skcipher_req);

	memcpy(iv, ctx->iv, ivsize);
	skcipher_request_set_crypt(&areq->cra_u.skcipher_req,
				   areq->tsgl,
				   areq->first_rsgl.sgl.sgt.sgl,
				   areq->outlen, iv);

	return crypto_skcipher_decrypt(&areq->cra_u.skcipher_req);
}
