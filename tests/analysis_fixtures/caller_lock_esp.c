/* esp4-style: the candidate function is always called with spin_lock held. */
#include <crypto/skcipher.h>

static int esp_xmit(struct esp_ctx *ctx, struct skcipher_request *req)
{
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}

static int esp_output(struct esp_ctx *ctx, struct sk_buff *skb)
{
	spin_lock(&ctx->lock);
	esp_xmit(ctx, ctx->req);
	spin_unlock(&ctx->lock);
	return 0;
}
