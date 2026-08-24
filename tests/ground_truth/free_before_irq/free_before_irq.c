/*
 * Ground-truth fixture: the generic "kfree() before free_irq()" ordering
 * shape (see rules/coccinelle/free_before_irq_sync.cocci for the
 * real-world precedent, CVE-2026-43426, usb/renesas_usbhs). Synthetic,
 * self-contained reduction of the underlying bug class. Not a working
 * exploit.
 */
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

struct sample_dev {
	int irq;
	void *ring;
};

static irqreturn_t sample_dev_isr(int irq, void *data)
{
	struct sample_dev *dev = data;
	(void)dev->ring;
	return IRQ_HANDLED;
}

static void sample_dev_remove(struct platform_device *pdev)
{
	struct sample_dev *dev = platform_get_drvdata(pdev);
	int irq = dev->irq;

#ifndef FIXED
	/* VULNERABLE: dev is freed before free_irq() unregisters and
	 * synchronizes with sample_dev_isr() -- an interrupt firing in
	 * this window dereferences freed memory. */
	kfree(dev);
	free_irq(irq, dev);
#else
	/* FIXED: free_irq() first -- unregisters the handler and waits
	 * for any in-flight invocation to finish before the free. */
	free_irq(irq, dev);
	kfree(dev);
#endif
}
