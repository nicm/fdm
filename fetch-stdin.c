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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	stdin_connect(struct account *);
int	stdin_disconnect(struct account *);
int	stdin_fetch(struct account *, struct mail *);
int	stdin_delete(struct account *);

struct fetch	fetch_stdin = { "stdin", "stdin",
				stdin_connect,
				NULL,
				stdin_fetch,
				stdin_delete,
				NULL,
				stdin_disconnect };

int
stdin_connect(struct account *a)
{
	struct stdin_data	*data;

	if (isatty(STDIN_FILENO)) {
		log_warnx("%s: stdin is a tty. ignoring", a->name);
		return (1);
	}

	data = a->data;

	if (fcntl(STDIN_FILENO, F_GETFL) == -1) {
		if (errno != EBADF)
			fatal("fcntl");
		log_warnx("%s: stdin is invalid", a->name);
		return (1);
	}

	data->io = io_create(STDIN_FILENO, NULL, IO_LF);
	if (conf.debug > 3)
		data->io->dup_fd = STDOUT_FILENO;

	data->complete = 0;

	return (0);
}

int
stdin_disconnect(struct account *a)
{
	struct stdin_data	*data;

	data = a->data;

	io_free(data->io);

	close(STDIN_FILENO);

	return (0);
}

int
stdin_delete(struct account *a)
{
	struct stdin_data	*data;
	char		        *line, *lbuf;
	size_t			 llen;

	data = a->data;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	for (;;) {
		if (io_poll(data->io, NULL) != 1)
			break;

		for (;;) {
			line = io_readline2(data->io, &lbuf, &llen);
			if (line == NULL)
				break;
		}
	}

	xfree(lbuf);
	return (0);
}

int
stdin_fetch(struct account *a, struct mail *m)
{
	struct stdin_data	*data;
	int		 	 error;
	char			*line, *cause, *lbuf;
	size_t			 len, llen;

	data = a->data;
	if (data->complete)
		return (FETCH_COMPLETE);

	if (m->data == NULL) {
		m->space = IO_BLOCKSIZE;
		m->base = m->data = xmalloc(m->space);
		m->size = 0;
		m->body = -1;
	}

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	for (;;) {
		if ((error = io_poll(data->io, &cause)) != 1) {
			/* normal close (error == 0) is fine */
			if (error == 0)
				break;
			log_warnx("%s: io_poll: %s", a->name, cause);
			xfree(cause);
			xfree(lbuf);
			return (FETCH_ERROR);
		}

		for (;;) {
			line = io_readline2(data->io, &lbuf, &llen);
			if (line == NULL)
				break;

			len = strlen(line);
			if (len == 0 && m->body == -1)
				m->body = m->size + 1;

			resize_mail(m, m->size + len + 1);

			if (len > 0)
				memcpy(m->data + m->size, line, len);
			/* append an LF */
			m->data[m->size + len] = '\n';
			m->size += len + 1;

			if (m->size > conf.max_size) {
				data->complete = 1;
				xfree(lbuf);
				return (FETCH_OVERSIZE);
			}
		}
	}

	if (m->size == 0) {
		log_warnx("%s: zero-length message", a->name);
		xfree(lbuf);
		return (FETCH_ERROR);
	}

 	data->complete = 1;
	xfree(lbuf);
	return (FETCH_SUCCESS);
}
