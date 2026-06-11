/* resolved.c (new) — fixed: ctx->iv snapshotted into a per-request buffer. */
#include <crypto/skcipher.h>

static int resolved_enc(struct sk_ctx *ctx, struct skcipher_request *req,
			unsigned int ivsize)
{
	u8 *iv = skcipher_request_ctx(req);

	memcpy(iv, ctx->iv, ivsize);
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, iv);
	return crypto_skcipher_encrypt(req);
}
