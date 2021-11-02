/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicholas.marriott@gmail.com>
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

void	fetch_imap_fill(struct account *, struct iolist *);
void	fetch_imap_desc(struct account *, char *, size_t);

int	fetch_imap_connect(struct account *);
void	fetch_imap_disconnect(struct account *);

struct fetch fetch_imap = {
	"imap",
	fetch_imap_state_init,

	fetch_imap_fill,
	imap_commit,	/* from imap-common.c */
	imap_abort,	/* from imap-common.c */
	imap_total,	/* from imap-common.c */
	fetch_imap_desc
};

/* Write line to server. */
int
fetch_imap_putln(struct account *a, const char *fmt, va_list ap)
{
	struct fetch_imap_data	*data = a->data;

	io_vwriteline(data->io, fmt, ap);

	return (0);
}

/* Write buffer to server. */
int
fetch_imap_putn(struct account *a, const char *buf, size_t len)
{
	struct fetch_imap_data	*data = a->data;

	io_write(data->io, buf, len);

	return (0);
}

/* Get line from server. */
int
fetch_imap_getln(struct account *a, struct fetch_ctx *fctx, char **line)
{
	struct fetch_imap_data	*data = a->data;

	*line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	return (0);
}

/* Fill io list. */
void
fetch_imap_fill(struct account *a, struct iolist *iol)
{
	struct fetch_imap_data	*data = a->data;

	ARRAY_ADD(iol, data->io);
}

/* Connect to server. */
int
fetch_imap_connect(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*cause;

	data->io = connectproxy(&data->server,
	    conf.verify_certs, conf.proxy, IO_CRLF, conf.timeout, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	return (0);
}

/* Close connection. */
void
fetch_imap_disconnect(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	if (data->io != NULL) {
		io_close(data->io);
		io_free(data->io);
		data->io = NULL;
	}
}

/* IMAP initial state. */
int
fetch_imap_state_init(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	data->connect = fetch_imap_connect;
	data->getln = fetch_imap_getln;
	data->putln = fetch_imap_putln;
	data->putn = fetch_imap_putn;
	data->disconnect = fetch_imap_disconnect;

	data->src = data->server.host;

	return (imap_state_init(a, fctx));
}

void
fetch_imap_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_imap_data	*data = a->data;
	char			*folders;

	folders = fmt_strings("folders ", data->folders);
	xsnprintf(buf, len,
	    "imap%s server \"%s\" port %s user \"%s\" %s",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user, folders);
	xfree(folders);
}
