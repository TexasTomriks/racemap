/*
 * sample_kernel fixture: net/tls/tls_sw.c (reduced).
 * Contains TWO vulnerable shared-state-to-async-crypto patterns.
 *
 * Both pass a shared tls_ctx field by pointer into an async skcipher request
 * without a per-request snapshot. A concurrent setsockopt/sendmsg path that
 * rewrites the field races the deferred crypto op.
 */
#include <crypto/skcipher.h>
#include <net/tls.h>

static int tls_do_encryption(struct sock *sk, struct tls_sw_context_tx *ctx,
			     struct aead_request *aead_req)
{
	struct scatterlist *src = ctx->sg_aead_in;
	struct scatterlist *dst = ctx->sg_aead_out;
	struct skcipher_request *req = ctx->skcipher_req;

	/* VULNERABLE #1: ctx->iv shared, no snapshot before async encrypt. */
	skcipher_request_set_crypt(req, src, dst,
				   ctx->data_len, ctx->iv);

	return crypto_skcipher_encrypt(req);
}

static int tls_do_decryption(struct sock *sk, struct tls_sw_context_rx *ctx,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout)
{
	struct skcipher_request *req = ctx->skcipher_req;

	/* VULNERABLE #2: ctx->info (rec seq / nonce) shared, no snapshot. */
	skcipher_request_set_crypt(req, sgin, sgout,
				   ctx->cryptlen, ctx->info);

	return crypto_skcipher_decrypt(req);
}
