// racemap Pattern C — vmsplice(): get_user_pages() result fed to a crypto
// request without set_page_dirty/put_page (user page aliased, no COW).
//
// Output: // RACEMAP:<file>:<line>:gup pages
// Run: spatch --sp-file vmsplice_gup_cow.cocci --dir <kernel>/fs

virtual report

@race exists@
expression uaddr, n, flags, pages, areq, sg, slen;
position p;
@@
  get_user_pages@p(uaddr, n, flags, pages)
  ... when != set_page_dirty(...)
      when != put_page(...)
      when != copy_page(...)
  aead_request_set_crypt(areq, sg, sg, slen, ...)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(p[0], "RACEMAP:%s:%s:gup pages" % (p[0].file, p[0].line))
