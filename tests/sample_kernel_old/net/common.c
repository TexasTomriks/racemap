/* common.c — vulnerable in both old and new (PERSISTENT finding). */
#include <crypto/skcipher.h>

static int common_enc(struct sk_ctx *ctx, struct skcipher_request *req)
{
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}
