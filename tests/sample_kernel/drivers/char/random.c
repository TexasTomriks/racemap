/*
 * sample_kernel fixture: drivers/char/random.c (reduced).
 * Contains TWO CLEAN patterns: the shared state is snapshotted into a
 * per-request buffer under lock before the async crypto request, so racemap's
 * static rule fires but the triage filter must exonerate them (likely_safe).
 * These exercise the false-positive-reduction path.
 */
#include <crypto/skcipher.h>

static int crng_reseed(struct crng_ctx *ctx, struct skcipher_request *req,
		       struct scatterlist *sg, unsigned int ivsize)
{
	u8 local_iv[16];

	/* CLEAN #1: snapshot ctx->iv under lock before the async op. */
	memcpy(local_iv, ctx->iv, ivsize);
	skcipher_request_set_crypt(req, sg, sg, ctx->len, local_iv);

	return crypto_skcipher_encrypt(req);
}

static int crng_make_state(struct crng_ctx *ctx, struct skcipher_request *req,
			   struct scatterlist *sg, unsigned int ivsize)
{
	u8 snap_iv[16];

	/* CLEAN #2: snapshot ctx->iv under lock before the async op. */
	memcpy(snap_iv, ctx->iv, ivsize);
	skcipher_request_set_crypt(req, sg, sg, ctx->len, snap_iv);

	return crypto_skcipher_decrypt(req);
}
