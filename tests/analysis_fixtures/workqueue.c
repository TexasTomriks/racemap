/* A workqueue deferred path runs near the shared access. */
#include <crypto/skcipher.h>
#include <linux/workqueue.h>

static void crypt_work(struct work_struct *w) { }

static int sched_crypt(struct ctx *ctx, struct skcipher_request *req)
{
	INIT_WORK(&ctx->work, crypt_work);
	queue_work(ctx->wq, &ctx->work);
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	return crypto_skcipher_encrypt(req);
}
