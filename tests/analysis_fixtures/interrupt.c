/* The candidate path runs in interrupt context. */
#include <crypto/skcipher.h>

static int rx_crypt(struct ctx *ctx, struct skcipher_request *req)
{
	if (in_interrupt())
		ctx->flags |= 1;
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}
