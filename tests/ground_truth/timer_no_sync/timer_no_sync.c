/*
 * Ground-truth fixture: the generic "timer_delete() without _sync before
 * free" shape (see rules/coccinelle/timer_delete_no_sync_before_free.cocci
 * for the real-world precedent, CVE-2026-23281, wifi/libertas). Synthetic,
 * self-contained reduction of the underlying bug class. Not a working
 * exploit.
 */
#include <linux/timer.h>
#include <linux/slab.h>

struct sample_dev {
	struct timer_list poll_timer;
};

extern void sample_dev_poll_timeout(struct timer_list *t);

static void sample_dev_free(struct sample_dev *dev)
{
#ifndef FIXED
	/* VULNERABLE: non-synchronizing timer_delete() -- an in-flight
	 * timer callback can still be running (and about to touch dev)
	 * when kfree() below releases the memory. */
	timer_delete(&dev->poll_timer);
	kfree(dev);
#else
	/* FIXED: synchronous variant waits for any in-flight callback to
	 * finish before we free the memory it might touch. */
	timer_delete_sync(&dev->poll_timer);
	kfree(dev);
#endif
}
