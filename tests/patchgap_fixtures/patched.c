/* patched.c — same pattern but WITH the patch signature (buf->flags = 0). */
#include <linux/pipe_fs_i.h>

static void push_buf(struct pipe_inode_info *pipe, unsigned int head,
		     struct page *page, size_t off, size_t len)
{
	struct pipe_buffer *buf = &pipe->bufs[head & (pipe->ring_size - 1)];

	buf->flags = 0;
	buf->page = page;
	buf->offset = off;
	buf->len = len;
	if (PageAnon(page))
		buf->flags |= PIPE_BUF_FLAG_CAN_MERGE;
}
