/*
 * mystery_driver.c — a realistic (fictional) NIC offload driver.
 *
 * INTENTIONAL RACE: see line 60.
 *   The TX path encrypts each frame with ctx->iv handed straight into the async
 *   skcipher request (no per-request snapshot). A workqueue callback
 *   (myx_refresh_iv_work) concurrently rewrites ctx->iv via get_random_bytes().
 *   Under concurrent execution the in-flight encryption observes a torn / rotated
 *   IV, breaking confidentiality — exactly the algif_skcipher class of bug.
 *   This is invisible to single-threaded reading: each function looks fine on
 *   its own; only the cross-thread interleaving is unsafe.
 *
 * racemap should flag the skcipher_request_set_crypt(... ctx->iv) site as a
 * likely race, and taint should observe ctx->iv propagating into a lockless
 * helper (myx_stage_iv).
 */
#include <crypto/skcipher.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/netdevice.h>

struct myx_ctx {
	struct crypto_skcipher	*tfm;
	struct skcipher_request	*req;
	struct scatterlist	*sg;
	struct work_struct	refresh;
	unsigned int		len;
	u8			iv[16];
	u8			stage_seq;
};

/* Lockless helper: touches the shared IV with no lock held. The TX path passes
 * ctx->iv straight into here, so the taint pass should escalate the candidate. */
static void myx_stage_iv(struct myx_ctx *ctx, u8 *iv)
{
	ctx->stage_seq = iv[0] ^ iv[15];
}

/* Workqueue callback — rotates the shared IV with no lock coordinating the TX
 * path. This is the racing writer. */
static void myx_refresh_iv_work(struct work_struct *w)
{
	struct myx_ctx *ctx = container_of(w, struct myx_ctx, refresh);

	get_random_bytes(ctx->iv, sizeof(ctx->iv));
}

/* TX encrypt path — runs on the hot path for every frame. */
static int myx_encrypt_frame(struct myx_ctx *ctx, struct sk_buff *skb)
{
	struct skcipher_request *req = ctx->req;
	int err;

	skcipher_request_set_callback(req, 0, NULL, NULL);
	/* INTENTIONAL RACE: ctx->iv is shared and rotated by the workqueue; it is
	 * handed to the async request with no per-request snapshot. */
	skcipher_request_set_crypt(req, ctx->sg, ctx->sg, ctx->len, ctx->iv);
	myx_stage_iv(ctx, ctx->iv);
	err = crypto_skcipher_encrypt(req);
	return err;
}

static netdev_tx_t myx_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct myx_ctx *ctx = netdev_priv(dev);

	if (myx_encrypt_frame(ctx, skb))
		goto drop;
	return NETDEV_TX_OK;
drop:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int myx_probe(struct net_device *dev)
{
	struct myx_ctx *ctx = netdev_priv(dev);

	INIT_WORK(&ctx->refresh, myx_refresh_iv_work);
	get_random_bytes(ctx->iv, sizeof(ctx->iv));
	schedule_work(&ctx->refresh);
	return 0;
}
