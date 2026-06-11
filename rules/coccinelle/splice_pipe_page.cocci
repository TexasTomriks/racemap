// racemap Pattern B — splice() uses a pipe_inode_info page without a .get
// callback / pipe_buf_get() / copy_page after the pipe lock is dropped.
//
// Output: // RACEMAP:<file>:<line>:pipe->bufs[].page
// Run: spatch --sp-file splice_pipe_page.cocci --dir <kernel>/fs

virtual report

@race exists@
expression pipe, i, sink, off, len;
position p;
@@
* sink_submit@p(sink, pipe->bufs[i].page, off, len)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(p[0], "RACEMAP:%s:%s:pipe->bufs[].page" % (p[0].file, p[0].line))

// SAFE: pipe_buf_get() taken before the page is consumed.
@safe exists@
expression pipe, i, sink, off, len;
@@
  pipe_buf_get(pipe, &pipe->bufs[i]);
  ...
  sink_submit(sink, pipe->bufs[i].page, off, len)
