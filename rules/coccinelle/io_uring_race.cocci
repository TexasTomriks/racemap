// racemap io_uring advanced — registered buffer (req->imu / io_mapped_ubuf) fed
// to a crypto or network op without a copy/unpin. Target: fs/io_uring/.
//
// Output: // RACEMAP:<file>:<line>:io_mapped_ubuf
// Run: spatch --sp-file io_uring_race.cocci --dir <kernel>/io_uring

virtual report

// Registered buffer sent over the network without a copy.
@netsend exists@
expression sock, msg;
identifier imu;
position p;
@@
* kernel_sendmsg@p(sock, msg, imu->bvec, ...)

@script:python depends on netsend && report@
p << netsend.p;
@@
coccilib.report.print_report(p[0], "RACEMAP:%s:%s:io_mapped_ubuf" % (p[0].file, p[0].line))

// Registered buffer fed to crypto in-place without a copy.
@cryptbuf exists@
expression req, n, iv;
identifier imu;
position q;
@@
* skcipher_request_set_crypt@q(req, imu->bvec, imu->bvec, n, iv)

@script:python depends on cryptbuf && report@
q << cryptbuf.q;
@@
coccilib.report.print_report(q[0], "RACEMAP:%s:%s:req->imu" % (q[0].file, q[0].line))
