// racemap Pattern A — io_uring registered buffer (req->imu) fed to a kernel
// crypto/network op without a copy or unpin before reuse.
//
// Output: // RACEMAP:<file>:<line>:req->imu
// Run: spatch --sp-file io_uring_fixed_buffer.cocci --dir <kernel>/io_uring

virtual report

@race exists@
expression req, dst, len, iv;
identifier imu;
position p;
@@
  skcipher_request_set_crypt@p(req, imu->bvec, dst, len, iv)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(p[0], "RACEMAP:%s:%s:req->imu" % (p[0].file, p[0].line))

// SAFE: a bounce copy + unpin precedes the request (suppressed from output).
@safe exists@
expression req, sg, len, iv, kbuf, src;
identifier imu;
@@
  memcpy(kbuf, src, ...);
  ... when != imu->bvec
  unpin_user_page(...);
  ... when != imu->bvec
  skcipher_request_set_crypt(req, sg, sg, len, iv)
