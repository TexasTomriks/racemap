/*
 * Ground-truth fixture: CVE-2022-2590 (shmem/COW mmap_lock race).
 * Modeled on the class of bugs where a copy_{from,to}_user runs inside an
 * mmap_read_lock() section while the VMA / page mapping can be changed
 * concurrently, so the fault is resolved against a stale VMA.
 *
 * racemap must flag the vulnerable variant as likely_race: the user copy
 * happens under a read lock with no re-validation of VMA stability.
 */
#include <linux/mm.h>
#include <linux/uaccess.h>

static long fault_copy(struct mm_struct *mm, unsigned long addr,
		       void __user *uptr, void *kbuf, size_t len)
{
	struct vm_area_struct *vma;
	long ret;

#ifndef FIXED
	/* VULNERABLE: copy under the read lock with no stability re-check; a
	 * concurrent unmap/COW can swap the page under us. */
	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	ret = copy_from_user(kbuf, uptr, len);
	mmap_read_unlock(mm);
	return ret;
#else
	/* FIXED: re-validate the VMA is still stable for the address before the
	 * user copy; bail to a retry otherwise. */
	mmap_read_lock(mm);
	vma = vma_lookup(mm, addr);
	if (!vma || (vma->vm_flags & VM_FAULT_RETRY)) {
		mmap_read_unlock(mm);
		return -EAGAIN;
	}
	ret = copy_from_user(kbuf, uptr, len);
	mmap_read_unlock(mm);
	return ret;
#endif
}
