// racemap CVE-2022-0847 (Dirty Pipe) — PIPE_BUF_FLAG_CAN_MERGE OR'd into a
// pipe_buffer whose ->flags was never initialised / page ownership unchecked.
//
// Output: // RACEMAP:<file>:<line>:buf->flags CAN_MERGE
// Run: spatch --sp-file cve_2022_0847_dirtypipe.cocci --dir <kernel>

virtual report

@race exists@
identifier buf;
position p;
@@
* buf->flags |=@p PIPE_BUF_FLAG_CAN_MERGE

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(p[0], "RACEMAP:%s:%s:buf->flags CAN_MERGE" % (p[0].file, p[0].line))

// SAFE: flags zero-initialised before CAN_MERGE is considered.
@safe@
identifier buf;
@@
  buf->flags = 0;
  ...
  buf->flags |= PIPE_BUF_FLAG_CAN_MERGE
