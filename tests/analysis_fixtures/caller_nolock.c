/* The candidate function is called WITHOUT any lock held. */
#include <crypto/skcipher.h>

static int raw_xmit(struct esp_ctx *ctx, struct skcipher_request *req)
{
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}

static int raw_output(struct esp_ctx *ctx, struct sk_buff *skb)
{
	raw_xmit(ctx, ctx->req);
	return 0;
}
