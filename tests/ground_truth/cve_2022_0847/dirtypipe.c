/*
 * Ground-truth fixture: CVE-2022-0847 (Dirty Pipe).
 * Based on the public patch (commit 9d2231c5d74e "lib/iov_iter: initialize
 * "flags" in new pipe_buffer").
 *
 * Root cause: a newly allocated pipe_buffer's ->flags field was left
 * uninitialised, so a stale PIPE_BUF_FLAG_CAN_MERGE could let a splice of
 * read-only page-cache pages be merged into and overwritten via pipe_write(),
 * bypassing file permissions. The fix zero-initialises buf->flags before any
 * CAN_MERGE flag is considered.
 *
 * racemap must flag the vulnerable variant as likely_race (no copy-on-write /
 * ownership guard on the merged page).
 */
#include <linux/pipe_fs_i.h>

static void push_pipe_buf(struct pipe_inode_info *pipe, unsigned int head,
			  struct page *page, size_t offset, size_t len)
{
	struct pipe_buffer *buf = &pipe->bufs[head & (pipe->ring_size - 1)];

#ifndef FIXED
	/* VULNERABLE: flags never initialised; stale CAN_MERGE allows writing
	 * into a shared, read-only page-cache page. */
	buf->page = page;
	buf->offset = offset;
	buf->len = len;
	buf->flags |= PIPE_BUF_FLAG_CAN_MERGE;
#else
	/* FIXED: zero-initialise flags before deciding CAN_MERGE, so a borrowed
	 * (unowned) page can never be merged into. */
	buf->flags = 0;
	buf->page = page;
	buf->offset = offset;
	buf->len = len;
	if (PageAnon(page))
		buf->flags |= PIPE_BUF_FLAG_CAN_MERGE;
#endif
}
