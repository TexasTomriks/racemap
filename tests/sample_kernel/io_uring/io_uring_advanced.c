/*
 * io_uring/io_uring_advanced.c — two advanced io_uring registered-buffer races.
 * Pattern 1: registered buffer (req->imu) fed to crypto without copy.
 * Pattern 2: io_mapped_ubuf sent over the network without copy.
 * Each has a vulnerable variant and a fixed (-DFIXED) variant.
 */
#include <crypto/skcipher.h>
#include <linux/io_uring.h>
#include <net/sock.h>

static int io_adv_crypt(struct io_kiocb *req, struct skcipher_request *sreq, size_t n)
{
	struct io_mapped_ubuf *imu = req->imu;
#ifndef FIXED
	/* VULNERABLE: registered buffer used in-place by crypto, no copy. */
	skcipher_request_set_crypt(sreq, imu->bvec, imu->bvec, n, NULL);
	return crypto_skcipher_encrypt(sreq);
#else
	/* FIXED: bounce-copy and unpin before the async crypto op. */
	u8 *kbuf = sreq_scratch(sreq);

	memcpy(kbuf, page_address(imu->bvec[0].bv_page), n);
	unpin_user_page(imu->bvec[0].bv_page);
	skcipher_request_set_crypt(sreq, kbuf_sg(kbuf), kbuf_sg(kbuf), n, NULL);
	return crypto_skcipher_encrypt(sreq);
#endif
}

static int io_adv_send(struct io_kiocb *req, struct socket *sock, size_t n)
{
	struct io_mapped_ubuf *imu = req->imu;
	struct kvec vec;
	struct msghdr msg = {0};

#ifndef FIXED
	/* VULNERABLE: registered buffer sent over the network with no copy. */
	vec.iov_base = page_address(imu->bvec[0].bv_page);
	vec.iov_len = n;
	return kernel_sendmsg(sock, &msg, &vec, 1, n);
#else
	/* FIXED: copy into a kernel buffer before the network send. */
	u8 kbuf[64];

	memcpy(kbuf, page_address(imu->bvec[0].bv_page), n);
	vec.iov_base = kbuf;
	vec.iov_len = n;
	return kernel_sendmsg(sock, &msg, &vec, 1, n);
#endif
}
