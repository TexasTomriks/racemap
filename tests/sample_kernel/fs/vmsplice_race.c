/*
 * sample_kernel fixture: fs/vmsplice_race.c
 * Pattern C — vmsplice() user pages aliased into crypto without COW.
 *
 * get_user_pages() pins user pages which are fed straight into an AEAD request.
 * Userspace still maps the same pages and can mutate them during the operation.
 * The fix marks the pages dirty and drops the pin (put_page) before reuse, and
 * operates on a copied page rather than the user alias.
 */
#include <crypto/aead.h>
#include <linux/mm.h>

static int vmsplice_crypt(struct aead_request *areq, unsigned long uaddr,
			  struct scatterlist *sgin, struct scatterlist *sgout,
			  size_t len)
{
	struct page *pages[1];

#ifndef FIXED
	/* VULNERABLE: user pages pinned and used directly, no dirty/put_page. */
	get_user_pages(uaddr, 1, FOLL_WRITE, pages);
	sg_set_page(sgin, pages[0], len, 0);
	aead_request_set_crypt(areq, sgin, sgout, len, NULL);
	return crypto_aead_encrypt(areq);
#else
	/* FIXED: pin, copy out, then set_page_dirty + put_page before reuse. */
	struct page *kpage = alloc_page(GFP_KERNEL);

	get_user_pages(uaddr, 1, FOLL_WRITE, pages);
	copy_page(page_address(kpage), page_address(pages[0]));
	set_page_dirty(pages[0]);
	put_page(pages[0]);
	sg_set_page(sgin, kpage, len, 0);
	aead_request_set_crypt(areq, sgin, sgout, len, NULL);
	return crypto_aead_encrypt(areq);
#endif
}
