// racemap: a function dereferences a SECOND inode reached through a
// pointer field on its primary inode argument (obj->lfield->i_mapping)
// without pinning that second inode via igrab() first. Unlike an inode's
// own fields (safe by the normal file/inode lifecycle the caller already
// established), a pointer to a SEPARATE, independently-lifecycled inode
// (a shadow/COW/atomic-write inode, a linked special inode, etc.) can be
// concurrently evicted and freed by an unrelated path (f2fs_evict_inode()
// clearing and iput()-ing it, for one) at any time this function doesn't
// itself hold a reference on it -- CWE-416 UAF.
//
// Ground truth: multiple f2fs "atomic: fix UAF issue on
// f2fs_inode_info.atomic_inode" fixes (e.g. commit e0288584baa5) --
// ra_data_block() and move_data_block() (fs/f2fs/gc.c) dereferenced
// F2FS_I(inode)->atomic_inode->i_mapping directly during garbage
// collection while a concurrent f2fs_evict_inode() on the atomic_inode
// cleared the pointer and freed it. Reachable via
// ioctl(F2FS_IOC_GARBAGE_COLLECT_RANGE) racing inode eviction. Fixed by
// igrab()'ing the linked inode (under i_sem) before using its mapping,
// and iput()'ing it on every exit path.
//
// Scoped to `->i_mapping` specifically (not any field) -- this keeps the
// pattern targeted at genuinely inode-typed linked objects without
// needing struct-type information Coccinelle doesn't have here, and
// matches the exact fidelity of the one ground-truth bug class found so
// far. May need broadening (or a database-driven per-field-name spec, cf.
// queuemap's model) if a similar bug is found through a different
// second-hop field.
//
// Detects: obj->lfield->i_mapping used, with no igrab(obj->lfield) call
// anywhere earlier in the same function.
// Exonerates: igrab(obj->lfield) called first.
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file linked_inode_no_igrab.cocci -D report --dir <kernel>/fs

virtual report

@race exists@
identifier func;
expression obj;
identifier lfield;
position p;
@@
  func(...)
  {
  ...
  when != igrab(obj->lfield)
  obj->lfield@p->i_mapping
  ...
  }

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:linked_inode" % (p[0].file, p[0].line)
)

@safe exists@
identifier func;
expression obj;
identifier lfield;
@@
  func(...)
  {
  ...
  igrab(obj->lfield);
  ... when any
  obj->lfield->i_mapping
  ...
  }
