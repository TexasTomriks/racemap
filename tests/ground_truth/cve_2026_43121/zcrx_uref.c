/*
 * Ground-truth fixture: CVE-2026-43121, "io_uring/zcrx: fix user_ref race
 * between scrub and refill paths".
 *
 * Root cause: io_zcrx_put_niov_uref() used a non-atomic check-then-decrement
 * (atomic_read() then a separate atomic_dec()) on a shared refcount, racing
 * a concurrent atomic_xchg() on the same counter from io_zcrx_scrub()
 * (which does not hold the same lock). Both sides could observe the
 * pre-race value and proceed, double-freeing the underlying niov onto a
 * freelist -- further pushes then wrote out of bounds past the freelist
 * array into the adjacent slab object. Fixed by replacing the read-then-dec
 * with a single atomic_try_cmpxchg() loop.
 *
 * racemap must flag the vulnerable variant as likely_race and exonerate the
 * cmpxchg variant. Synthetic test input -- not a working exploit.
 */
#include <linux/atomic.h>
#include <linux/compiler.h>

struct net_iov { atomic_t user_refs; };

static inline atomic_t *io_get_user_counter(struct net_iov *niov)
{
	return &niov->user_refs;
}

static bool io_zcrx_put_niov_uref(struct net_iov *niov)
{
	atomic_t *uref = io_get_user_counter(niov);

#ifndef FIXED
	/* VULNERABLE: check and decrement are two separate atomic ops, not
	 * one atomic read-modify-write -- a concurrent atomic_xchg() on the
	 * same counter can race in between. */
	if (unlikely(!atomic_read(uref)))
		return false;
	atomic_dec(uref);
#else
	int old;

	/* FIXED: a single atomic compare-and-swap loop. */
	old = atomic_read(uref);
	do {
		if (unlikely(old == 0))
			return false;
	} while (!atomic_try_cmpxchg(uref, &old, old - 1));
#endif

	return true;
}
