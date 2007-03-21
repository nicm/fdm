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
void	 fetch_stdin_fill(struct account *, struct io **, u_int *);
int	 fetch_stdin_finish(struct account *, int);
int	 fetch_stdin_fetch(struct account *, struct mail *);
int	 fetch_stdin_done(struct account *, struct mail *);
void	 fetch_stdin_desc(struct account *, char *, size_t);

struct fetch fetch_stdin = {
	"stdin",
	{ NULL, NULL },
	fetch_stdin_start,
	fetch_stdin_fill,
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

	data->llen = IO_LINESIZE;
	data->lbuf = xmalloc(data->llen);

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

	data->lines = 0;
	data->bodylines = -1;

	return (FETCH_SUCCESS);
}

void
fetch_stdin_fill(struct account *a, struct io **iop, u_int *n)
{
	struct fetch_stdin_data	*data = a->data;

	iop[(*n)++] = data->io;
}

int
fetch_stdin_finish(struct account *a, unused int aborted)
{
	struct fetch_stdin_data	*data = a->data;

	if (data->io != NULL)
		io_free(data->io);

	close(STDIN_FILENO);

	xfree(data->lbuf);

	return (FETCH_SUCCESS);
}

int
fetch_stdin_done(struct account *a, struct mail *m)
{
	struct fetch_stdin_data	*data = a->data;
	char		        *line;

	if (m->decision == DECISION_KEEP)
		return (FETCH_SUCCESS);

	while (io_pollline2(data->io,
	    &line, &data->lbuf, &data->llen, NULL) == 1)
		;

	return (FETCH_SUCCESS);
}

int
fetch_stdin_fetch(struct account *a, struct mail *m)
{
	struct fetch_stdin_data	*data = a->data;
	int		 	 error;
	char			*line, *cause;
	size_t			 len;

	if (data->complete)
		return (FETCH_COMPLETE);

	if (m->data == NULL) {
		mail_open(m, IO_BLOCKSIZE);
		m->size = 0;

		m->auxdata = NULL;
		m->auxfree = NULL;

		default_tags(&m->tags, NULL, a);
	}

restart:
	/*
	 * There can only ever be one mail on stdin, so the normal reentrancy
	 * becomes irrelevent. Which is good since we need to detect when the
	 * fd is closed.
	 */
	error = io_pollline2(data->io, &line, &data->lbuf, &data->llen, &cause);
	switch (error) {
	case 0:
		/* normal close (error == 0) is fine */
		goto complete;
	case -1:
		if (errno == EAGAIN)
			return (FETCH_AGAIN);
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}

	len = strlen(line);
	if (len == 0 && m->body == -1) {
		m->body = m->size + 1;
		data->bodylines = 0;
	}
	data->lines++;
	if (data->bodylines != -1)
		data->bodylines++;

	resize_mail(m, m->size + len + 1);
	if (len > 0)
		memcpy(m->data + m->size, line, len);

	/* append an LF */
	m->data[m->size + len] = '\n';
	m->size += len + 1;

	if (m->size > conf.max_size) {
		data->complete = 1;
		return (FETCH_OVERSIZE);
	}

	goto restart;

complete:
 	data->complete = 1;

	if (m->size == 0)
		return (FETCH_EMPTY);

	add_tag(&m->tags, "lines", "%u", data->lines);
	if (data->bodylines == -1) {
		add_tag(&m->tags, "body_lines", "0");
		add_tag(&m->tags, "header_lines", "%u", data->lines - 1);
	} else {
		add_tag(&m->tags, "body_lines", "%d", data->bodylines - 1);
		add_tag(&m->tags, "header_lines", "%d", data->lines -
		    data->bodylines);
	}

	return (FETCH_SUCCESS);
}

void
fetch_stdin_desc(unused struct account *a, char *buf, size_t len)
{
	strlcpy(buf, "stdin", len);
}
