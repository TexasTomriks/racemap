/* resolved.c (old) — vulnerable: ctx->iv handed to async request directly. */
#include <crypto/skcipher.h>

static int resolved_enc(struct sk_ctx *ctx, struct skcipher_request *req)
{
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}
