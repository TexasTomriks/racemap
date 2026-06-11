// racemap CVE-2022-2590 — copy_{from,to}_user inside an mmap_read_lock section
// with no VMA stability re-check (vma_lookup) after the lock is taken.
//
// Output: // RACEMAP:<file>:<line>:copy_user under mmap_read_lock
// Run: spatch --sp-file cve_2022_2590_mmap.cocci --dir <kernel>

virtual report

@race exists@
expression mm, dst, src, len;
position p;
@@
  mmap_read_lock(mm)
  ... when != vma_lookup(mm, ...)
  \(copy_from_user@p(dst, src, len)\|copy_to_user@p(dst, src, len)\)
  ...
  mmap_read_unlock(mm)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(p[0], "RACEMAP:%s:%s:copy_user under mmap_read_lock" % (p[0].file, p[0].line))
