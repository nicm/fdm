/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <string.h>

#include "fdm.h"

/* Create a buffer. */
struct buffer *
buffer_create(size_t size)
{
	struct buffer	*b;

	b = xcalloc(1, sizeof *b);

	b->base = xmalloc(size);
	b->space = size;

	return (b);
}

/* Destroy a buffer. */
void
buffer_destroy(struct buffer *b)
{
	xfree(b->base);
	xfree(b);
}

/* Empty a buffer. */
void
buffer_clear(struct buffer *b)
{
	b->size = 0;
	b->off = 0;
}

/* Ensure free space for size in buffer. */
void
buffer_ensure(struct buffer *b, size_t size)
{
	if (BUFFER_FREE(b) >= size)
		return;

	if (b->off > 0) {
		if (b->size > 0)
			memmove(b->base, b->base + b->off, b->size);
		b->off = 0;
	}

	ENSURE_FOR(b->base, b->space, b->size, size);
}

/* Adjust buffer after data appended. */
void
buffer_added(struct buffer *b, size_t size)
{
	if (b->size + size > b->space)
		log_fatalx("buffer_added: overflow");

	b->size += size;
}

/* Remove added data from buffer. */
void
buffer_trimmed(struct buffer *b, size_t size)
{
	if (size > b->size)
		log_fatalx("buffer_trimmed: underflow");

	b->size -= size;
}

/* Remove data from start of buffer after it is used. */
void
buffer_removed(struct buffer *b, size_t size)
{
	if (size > b->size)
		log_fatalx("buffer_removed: underflow");

	b->size -= size;
	b->off += size;
}

/* Copy data into a buffer. */
void
buffer_write(struct buffer *b, const void *data, size_t size)
{
	buffer_ensure(b, size);
	memcpy(BUFFER_IN(b), data, size);
	buffer_added(b, size);
}

/* Copy data out of a buffer. */
void
buffer_read(struct buffer *b, void *data, size_t size)
{
	if (size > b->size)
		log_fatalx("buffer_read: underflow");

	memcpy(data, BUFFER_OUT(b), size);
	buffer_removed(b, size);
}
