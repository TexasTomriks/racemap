/* A memory barrier sits between the shared access and the async call. */
#include <crypto/skcipher.h>

static int do_crypt(struct ctx *ctx, struct skcipher_request *req)
{
	u8 iv0 = READ_ONCE(ctx->iv[0]);

	smp_rmb();
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}
