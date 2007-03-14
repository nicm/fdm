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
#include "fetch.h"

int	 fetch_stdin_start(struct account *);
int	 fetch_stdin_finish(struct account *);
int	 fetch_stdin_fetch(struct account *, struct mail *);
int	 fetch_stdin_done(struct account *, enum decision);
void	 fetch_stdin_desc(struct account *, char *, size_t);

struct fetch fetch_stdin = {
	{ NULL, NULL },
	fetch_stdin_start,
	NULL,
	fetch_stdin_fetch,
	NULL,
	fetch_stdin_done,
	fetch_stdin_finish,
	fetch_stdin_desc
};

int
fetch_stdin_start(struct account *a)
{
	struct fetch_stdin_data	*data = a->data;

	if (isatty(STDIN_FILENO)) {
		log_warnx("%s: stdin is a tty. ignoring", a->name);
		return (FETCH_ERROR);
	}

	if (fcntl(STDIN_FILENO, F_GETFL) == -1) {
		if (errno != EBADF)
			fatal("fcntl");
		log_warnx("%s: stdin is invalid", a->name);
		return (FETCH_ERROR);
	}

	data->io = io_create(STDIN_FILENO, NULL, IO_LF, conf.timeout);
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	data->complete = 0;

	return (FETCH_SUCCESS);
}

int
fetch_stdin_finish(struct account *a)
{
	struct fetch_stdin_data	*data = a->data;

	if (data->io != NULL)
		io_free(data->io);

	close(STDIN_FILENO);

	return (FETCH_SUCCESS);
}

int
fetch_stdin_done(struct account *a, enum decision d)
{
	struct fetch_stdin_data	*data = a->data;
	char		        *line, *lbuf;
	size_t			 llen;

	if (d == DECISION_KEEP)
		return (FETCH_SUCCESS);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	while (io_pollline2(data->io, &line, &lbuf, &llen, NULL) == 1)
		;

	xfree(lbuf);
	return (FETCH_SUCCESS);
}

int
fetch_stdin_fetch(struct account *a, struct mail *m)
{
	struct fetch_stdin_data	*data = a->data;
	u_int			 lines;
	int		 	 error, bodylines;
	char			*line, *cause, *lbuf;
	size_t			 len, llen;

	if (data->complete)
		return (FETCH_COMPLETE);

	if (m->data == NULL) {
		mail_open(m, IO_BLOCKSIZE);
		m->size = 0;
	}

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	lines = 0;
	bodylines = -1;
	for (;;) {
		error = io_pollline2(data->io, &line, &lbuf, &llen, &cause);
		if (error != 1) {
			/* normal close (error == 0) is fine */
			if (error == 0)
				break;
			log_warnx("%s: %s", a->name, cause);
			xfree(cause);
			xfree(lbuf);
			return (FETCH_ERROR);
		}

		len = strlen(line);
		if (len == 0 && m->body == -1) {
			m->body = m->size + 1;
			bodylines = 0;
		}
		lines++;
		if (bodylines != -1)
			bodylines++;

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
	if (m->size == 0) {
		data->complete = 1;
		xfree(lbuf);
		return (FETCH_EMPTY);
	}

	add_tag(&m->tags, "lines", "%u", lines);
	if (bodylines == -1) {
		add_tag(&m->tags, "body_lines", "0");
		add_tag(&m->tags, "header_lines", "%u", lines - 1);
	} else {
		add_tag(&m->tags, "body_lines", "%d", bodylines - 1);
		add_tag(&m->tags, "header_lines", "%d", lines - bodylines);
	}

 	data->complete = 1;
	xfree(lbuf);
	return (FETCH_SUCCESS);
}

void
fetch_stdin_desc(unused struct account *a, char *buf, size_t len)
{
	strlcpy(buf, "stdin", len);
}
