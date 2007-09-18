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

void	fetch_pop3_fill(struct account *, struct iolist *);
void	fetch_pop3_desc(struct account *, char *, size_t);

int	fetch_pop3_connect(struct account *);
void	fetch_pop3_disconnect(struct account *);
int	fetch_pop3_putln(struct account *, const char *, va_list);
int	fetch_pop3_getln(struct account *, struct fetch_ctx *, char **);

int	fetch_pop3_state_init(struct account *, struct fetch_ctx *);

struct fetch fetch_pop3 = {
	"pop3",
	fetch_pop3_state_init,

	fetch_pop3_fill,
	pop3_commit,	/* from pop3-common.c */
	pop3_abort,	/* from pop3-common.c */
	pop3_total,	/* from pop3-common.c */
	fetch_pop3_desc
};

/* Write line to server. */
int
fetch_pop3_putln(struct account *a, const char *fmt, va_list ap)
{
	struct fetch_pop3_data	*data = a->data;

	io_vwriteline(data->io, fmt, ap);

	return (0);
}

/* Get line from server. */
int
fetch_pop3_getln(struct account *a, struct fetch_ctx *fctx, char **line)
{
	struct fetch_pop3_data	*data = a->data;

	*line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	return (0);
}

/* Fill io list. */
void
fetch_pop3_fill(struct account *a, struct iolist *iol)
{
	struct fetch_pop3_data	*data = a->data;

	ARRAY_ADD(iol, data->io);
}

/* Connect to server. */
int
fetch_pop3_connect(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;
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
fetch_pop3_disconnect(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	if (data->io != NULL) {
		io_close(data->io);
		io_free(data->io);
		data->io = NULL;
	}
}

/* Initial POP3 state. */
int
fetch_pop3_state_init(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;

	data->connect = fetch_pop3_connect;
	data->getln = fetch_pop3_getln;
	data->putln = fetch_pop3_putln;
	data->disconnect = fetch_pop3_disconnect;

	data->src = data->server.host;

	return (pop3_state_init(a, fctx));
}

void
fetch_pop3_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_pop3_data	*data = a->data;

	xsnprintf(buf, len, "pop3%s server \"%s\" port %s user \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user);
}
