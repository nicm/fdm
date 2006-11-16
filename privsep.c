/* $Id$ */


/*
 * Copyright (c) 2006 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include "fdm.h"

u_int	nrecv = 0;
u_int	nsend = 0;

int
privsep_send(struct io *io, struct msg *msg, void *buf, size_t len)
{
	msg->n = nsend++;

	if (buf != NULL && len > 0)
		msg->size = len;
	else
		msg->size = 0;

	io_write(io, msg, sizeof *msg);
	if (io_flush(io, NULL) != 0)
		return (1);

	if (buf != NULL && len > 0) {
		io_write(io, buf, len);
		if (io_flush(io, NULL) != 0)
			return (1);
	}

	return (0);
}

int
privsep_recv(struct io *io, struct msg *msg, void **buf, size_t *len)
{
	if (len != NULL)
		*len = 0;
	if (buf != NULL)
		*buf = NULL;

	if (io_wait(io, sizeof *msg, NULL) != 0)
		return (1);
	if (io_read2(io, msg, sizeof *msg) != 0)
		return (1);

	if (msg->n != nrecv)
		return (1);
	nrecv++;

	if (msg->size == 0)
		return (0);
	if (buf == NULL || len == NULL)
		return (1);

	*len = msg->size;
	if (io_wait(io, *len, NULL) != 0)
		return (1);
	if ((*buf = io_read(io, *len)) == NULL)
		return (1);

	return (0);
}
