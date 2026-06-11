/*
 * sample_kernel fixture: fs/splice_race.c
 * Pattern B — splice() pipe page used without a .get callback / copy.
 *
 * The splice path accesses pipe->bufs[].page directly after the pipe lock is
 * dropped, with a pipe_buf_operations table that has no .get callback. A racing
 * pipe writer can recycle the page. The fix takes a reference via pipe_buf_get()
 * (or copies the page) before handing it to the sink.
 */
#include <linux/pipe_fs_i.h>
#include <linux/splice.h>

#ifndef FIXED
/* VULNERABLE: ops table without a .get callback. */
static const struct pipe_buf_operations race_pipe_ops = {
	.release = generic_pipe_buf_release,
	.try_steal = generic_pipe_buf_try_steal,
};

static int splice_to_sink(struct pipe_inode_info *pipe, unsigned int i,
			  struct sink *sink)
{
	/* direct page access after the pipe lock was dropped, no get/copy. */
	struct page *page = pipe->bufs[i].page;

	return sink_submit(sink, page, pipe->bufs[i].offset, pipe->bufs[i].len);
}
#else
/* FIXED: ops table provides a .get callback and the path takes a ref. */
static const struct pipe_buf_operations race_pipe_ops = {
	.release = generic_pipe_buf_release,
	.try_steal = generic_pipe_buf_try_steal,
	.get = generic_pipe_buf_get,
};

static int splice_to_sink(struct pipe_inode_info *pipe, unsigned int i,
			  struct sink *sink)
{
	struct page *page = pipe->bufs[i].page;

	pipe_buf_get(pipe, &pipe->bufs[i]);   /* stable reference before use */
	return sink_submit(sink, page, pipe->bufs[i].offset, pipe->bufs[i].len);
}
#endif
