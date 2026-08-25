/*
 * Ground-truth fixture: f2fs "atomic: fix UAF issue on
 * f2fs_inode_info.atomic_inode" (commit e0288584baa5), reduced from
 * fs/f2fs/gc.c's ra_data_block(). See rules/coccinelle/
 * linked_inode_no_igrab.cocci for the exact commit reference. Not a
 * working exploit.
 */
#include <linux/fs.h>

struct f2fs_inode_info {
	struct inode vfs_inode;
	struct inode *atomic_inode;
};

extern struct f2fs_inode_info *F2FS_I(struct inode *inode);
extern bool f2fs_is_cow_file(struct inode *inode);
extern struct folio *f2fs_grab_cache_folio(struct address_space *mapping,
					   pgoff_t index, bool for_write);

static int ra_data_block(struct inode *inode, pgoff_t index)
{
	struct folio *folio;

#ifndef FIXED
	/* VULNERABLE: no igrab() on atomic_inode -- a concurrent
	 * f2fs_evict_inode() can clear and free it before/while this
	 * function dereferences its mapping. */
	struct address_space *mapping = f2fs_is_cow_file(inode) ?
			F2FS_I(inode)->atomic_inode->i_mapping : inode->i_mapping;

	folio = f2fs_grab_cache_folio(mapping, index, true);
#else
	struct inode *atomic_inode = NULL;
	struct address_space *mapping = inode->i_mapping;

	if (f2fs_is_cow_file(inode)) {
		atomic_inode = igrab(F2FS_I(inode)->atomic_inode);
		if (!atomic_inode)
			return -EBUSY;
		mapping = atomic_inode->i_mapping;
	}

	/* FIXED: atomic_inode is pinned for the duration of this
	 * function via igrab() above. */
	folio = f2fs_grab_cache_folio(mapping, index, true);
	if (atomic_inode)
		iput(atomic_inode);
#endif

	if (IS_ERR(folio))
		return PTR_ERR(folio);

	return 0;
}
