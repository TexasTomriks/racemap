/*
 * Ground-truth fixture: CVE-2026-46316 (arch/arm64/kvm/vgic/vgic-its.c,
 * vgic_its_invalidate_cache()). Reduced from the real upstream function
 * -- see rules/coccinelle/xa_erase_stale_iter.cocci for the exact commit
 * reference. Not a working exploit.
 */
#include <linux/xarray.h>

struct kvm;
struct vgic_irq;

extern void vgic_put_irq(struct kvm *kvm, struct vgic_irq *irq);

static void vgic_its_invalidate_cache(struct kvm *kvm, struct xarray *cache)
{
	struct vgic_irq *irq;
	unsigned long idx;

#ifndef FIXED
	/* VULNERABLE: xa_erase()'s return value is discarded; the stale
	 * iterated `irq` is used instead. Two concurrent drains that both
	 * observe the same entry before either erases it can both put it,
	 * double-dropping a single cache reference. */
	xa_for_each(cache, idx, irq) {
		xa_erase(cache, idx);
		vgic_put_irq(kvm, irq);
	}
#else
	/* FIXED: only the context that actually erased the entry (got a
	 * non-NULL return) drops its cache reference. */
	xa_for_each(cache, idx, irq) {
		irq = xa_erase(cache, idx);
		if (irq)
			vgic_put_irq(kvm, irq);
	}
#endif
}
