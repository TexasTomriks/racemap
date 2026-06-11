/*
 * sample_kernel fixture: io_uring/io_uring_crypto.c
 * Pattern A — io_uring fixed buffers fed to a crypto op without copy/unpin.
 *
 * A registered buffer (req->imu, an imported userspace mapping) is handed
 * straight to the crypto engine. Userspace can race the kernel and mutate the
 * still-mapped pages between submit and execute. The fix copies the imported
 * pages into a kernel-owned bounce buffer and unpins before reuse.
 *
 * Build the vulnerable variant by default; -DFIXED selects the patched form.
 */
#include <crypto/skcipher.h>
#include <linux/io_uring.h>

static int io_crypto_issue(struct io_kiocb *req, struct io_mapped_ubuf *imu,
			   struct skcipher_request *sreq, u8 *iv, size_t nbytes)
{
#ifndef FIXED
	/* VULNERABLE: imported user mapping used in-place, no copy, no unpin. */
	skcipher_request_set_crypt(sreq, imu->bvec, imu->bvec, nbytes, iv);
	return crypto_skcipher_encrypt(sreq);
#else
	/* FIXED: copy the imported buffer into a kernel page and unpin it
	 * before the async crypto op, so userspace can no longer alias it. */
	struct page *upage = imu->bvec[0].bv_page;
	u8 *kbuf = sreq_scratch(sreq);

	memcpy(kbuf, page_address(upage), nbytes);
	unpin_user_page(upage);
	skcipher_request_set_crypt(sreq, kbuf_sg(kbuf), kbuf_sg(kbuf), nbytes, iv);
	return crypto_skcipher_encrypt(sreq);
#endif
}
