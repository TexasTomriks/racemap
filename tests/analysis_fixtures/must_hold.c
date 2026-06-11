/* Candidate function annotated __must_hold — lock is required on entry. */
#include <crypto/skcipher.h>

static int crypt_one(struct ctx *ctx, struct skcipher_request *req) __must_hold(&ctx->lock)
{
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}
