/*
 * Ground-truth fixture: the fixed counterpart of the async-request pattern. The
 * shared state is copied into a per-request buffer before the setter is called,
 * so concurrent mutation no longer affects the in-flight operation. racemap
 * should classify this as likely_safe (snapshot taken). Synthetic test input —
 * not a working exploit.
 */
#include <crypto/skcipher.h>

static int _skcipher_recvmsg(struct socket *sock, struct msghdr *msg,
			     size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct sock *psk = ask->parent;
	struct alg_sock *pask = alg_sk(psk);
	struct skcipher_ctx *ctx = ask->private;
	struct crypto_skcipher *tfm = pask->private;
	unsigned int ivsize = crypto_skcipher_ivsize(tfm);
	struct af_alg_async_req *areq;
	u8 *iv;
	int err = 0;

	areq = af_alg_alloc_areq(sk, sizeof(*areq) +
				 crypto_skcipher_reqsize(tfm) + ivsize);
	if (IS_ERR(areq))
		return PTR_ERR(areq);

	/* FIXED: snapshot ctx->iv into a per-request buffer first. */
	iv = (u8 *)skcipher_request_ctx(&areq->cra_u.skcipher_req) +
	     crypto_skcipher_reqsize(tfm);
	memcpy(iv, ctx->iv, ivsize);

	skcipher_request_set_crypt(&areq->cra_u.skcipher_req,
				   areq->tsgl,
				   areq->first_rsgl.sgl.sgt.sgl,
				   areq->outlen, iv);

	err = crypto_skcipher_decrypt(&areq->cra_u.skcipher_req);
	return err;
}
