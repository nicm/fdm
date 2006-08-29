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
 
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	imap_connect(struct account *);
int	imap_disconnect(struct account *);
int	do_imap(struct account *, u_int *, struct mail *, int);

struct fetch	fetch_imap = { "imap", "imap",
			       imap_connect, 
			       imap_poll,
			       imap_fetch,
			       imap_delete,
			       imap_error,
			       imap_disconnect };

int
imap_connect(struct account *a)
{
	struct imap_data	*data;
	char			*cause;

	data = a->data;

	if ((data->fd = connectto(&data->server, &cause)) < 0) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	data->io = io_create(data->fd, NULL, IO_CRLF);
	if (conf.debug > 3)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = IMAP_CONNECTING;

	return (0);
}

int
imap_disconnect(struct account *a)
{
	struct imap_data	*data;

	data = a->data;

	io_free(data->io);

	close(data->fd);

	return (0);
}

void
imap_error(struct account *a)
{
	struct imap_data	*data;

	data = a->data;

	/** XXX **/
}

int
imap_poll(struct account *a, u_int *n)
{
	return (do_imap(a, n, NULL, 1));
}

int
imap_fetch(struct account *a, struct mail *m)
{
	return (do_imap(a, NULL, m, 0));
}

int
do_imap(struct account *a, u_int *n, struct mail *m, int is_poll)
{
	struct imap_data	*data;
	int		 	 res, flushing;
	char			*line, *lbuf;
	size_t			 llen;

	data = a->data;

	if (m != NULL)
		m->data = NULL;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	flushing = 0;
	do {
		if (io_poll(data->io) != 1) {
			line = "io_poll failed";
			goto error;
		}

		res = -1;
		do {
			line = io_readline2(data->io, &lbuf, &llen);
			if (line == NULL)
				break;
			
			switch (data->state) {
			case IMAP_CONNECTING:
				break;
				/** XXX **/
			}
		} while (res == -1);
	} while (res == -1);

	xfree(lbuf);
	io_flush(data->io);
	return (res);

error:
	log_warnx("%s: %s", a->name, line);

	xfree(lbuf);
	io_flush(data->io);
	return (FETCH_ERROR);
}

int
imap_delete(struct account *a)
{
	struct imap_data	*data;

	data = a->data;

	/** XXX **/

	return (0);
}
