/*
 * Ground-truth fixture: CVE-2026-46180 (wifi/brcmfmac,
 * brcmf_sdio_bus_stop()/brcmf_sdio_remove()). Reduced from the real
 * upstream function -- see
 * rules/coccinelle/kthread_stop_without_get_task.cocci for the exact
 * commit reference. Not a working exploit.
 */
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/signal.h>

struct sample_bus {
	struct task_struct *watchdog_tsk;
};

static void sample_bus_stop(struct sample_bus *bus)
{
	if (bus->watchdog_tsk) {
#ifndef FIXED
		/* VULNERABLE: no get_task_struct() -- the watchdog thread
		 * can exit and free its own task_struct in the window
		 * between send_sig() and kthread_stop(). */
		send_sig(SIGTERM, bus->watchdog_tsk, 1);
		kthread_stop(bus->watchdog_tsk);
#else
		/* FIXED: pin the task_struct's refcount for the sequence. */
		get_task_struct(bus->watchdog_tsk);
		send_sig(SIGTERM, bus->watchdog_tsk, 1);
		kthread_stop(bus->watchdog_tsk);
		put_task_struct(bus->watchdog_tsk);
#endif
		bus->watchdog_tsk = NULL;
	}
}
