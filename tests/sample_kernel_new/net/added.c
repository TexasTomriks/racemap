/* added.c (new only) — newly introduced vulnerable pattern (NEW finding). */
#include <crypto/skcipher.h>

static int added_enc(struct sk_ctx *ctx, struct skcipher_request *req)
{
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}
