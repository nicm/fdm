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

#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

int	 	 fetch_imap_start(struct account *, int *);
void	         fetch_imap_fill(struct account *, struct io **, u_int *);
int	 	 fetch_imap_finish(struct account *, int);
void		 fetch_imap_desc(struct account *, char *, size_t);

int printflike2	 fetch_imap_putln(struct account *, const char *, ...);
int		 fetch_imap_getln(struct account *, int, char **, int);
void		 fetch_imap_flush(struct account *);

struct fetch fetch_imap = {
	"imap",
	{ "imap", "imaps" },
	fetch_imap_start,
	fetch_imap_fill,
	imap_poll,	/* from imap-common.c */
	imap_fetch,	/* from imap-common.c */
	imap_purge,	/* from imap-common.c */
	imap_done,	/* from imap-common.c */
	fetch_imap_finish,
	fetch_imap_desc
};

int printflike2
fetch_imap_putln(struct account *a, const char *fmt, ...)
{
	struct fetch_imap_data	*data = a->data;

	va_list	ap;

	va_start(ap, fmt);
	io_vwriteline(data->io, fmt, ap);
	va_end(ap);

	return (0);
}

int
fetch_imap_getln(struct account *a, int type, char **line, int block)
{
	struct fetch_imap_data	*data = a->data;
	char		       **lbuf = &data->lbuf;
	size_t			*llen = &data->llen;
	char			*cause;
	int			 tag;

restart:
	if (!block) {
		*line = io_readline2(data->io, &data->lbuf, &data->llen);
		if (*line == NULL)
			return (1);
	} else {
		switch (io_pollline2(data->io, line, lbuf, llen, &cause)) {
		case 0:
			log_warnx("%s: connection unexpectedly closed",a->name);
			return (-1);
		case -1:
			log_warnx("%s: %s", a->name, cause);
			xfree(cause);
			return (-1);
		}
	}

	if (type == IMAP_RAW)
		return (0);
	tag = imap_tag(*line);
	switch (type) {
	case IMAP_TAGGED:
		if (tag == IMAP_TAG_NONE)
			goto restart;
		if (tag == IMAP_TAG_CONTINUE)
			goto invalid;
		if (tag != data->tag)
			goto invalid;
		break;
	case IMAP_UNTAGGED:
		if (tag != IMAP_TAG_NONE)
			goto invalid;
		break;
	case IMAP_CONTINUE:
		if (tag == IMAP_TAG_NONE)
			goto restart;
		if (tag != IMAP_TAG_CONTINUE)
			goto invalid;
		break;
	}

	return (0);

invalid:
	log_warnx("%s: unexpected data: %s", a->name, *line);
	return (-1);
}

void
fetch_imap_flush(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	io_flush(data->io, NULL);
}

int
fetch_imap_start(struct account *a, int *total)
{
	struct fetch_imap_data	*data = a->data;
	char			*cause;

	if (imap_start(a) != FETCH_SUCCESS)
		return (FETCH_ERROR);

	data->io = connectproxy(&data->server,
	    conf.proxy, IO_CRLF, conf.timeout, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	data->getln = fetch_imap_getln;
	data->putln = fetch_imap_putln;
	data->flush = fetch_imap_flush;
	data->src = data->server.host;

	if (imap_login(a) != 0)
		return (FETCH_ERROR);

	if (imap_select(a) != 0) {
		imap_abort(a);
		return (FETCH_ERROR);
	}

	*total = data->num;
	return (FETCH_SUCCESS);
}

void
fetch_imap_fill(struct account *a, struct io **iop, u_int *n)
{
	struct fetch_imap_data	*data = a->data;

	iop[(*n)++] = data->io;
}

int
fetch_imap_finish(struct account *a, int aborted)
{
	struct fetch_imap_data	*data = a->data;

	if (data->io != NULL) {
		if (aborted)
			imap_abort(a);
		else if (imap_close(a) != 0 || imap_logout(a) != 0) {
			imap_abort(a);
			goto error;
		}

		if (data->io != NULL) {
			io_close(data->io);
			io_free(data->io);
		}
	}

	return (imap_finish(a));

error:
	if (data->io != NULL) {
		io_close(data->io);
		io_free(data->io);
	}

	imap_finish(a);
	return (FETCH_ERROR);
}

void
fetch_imap_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_imap_data	*data = a->data;

	xsnprintf(buf, len,
	    "imap%s server \"%s\" port %s user \"%s\" folder \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user, data->folder);
}
