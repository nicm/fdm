/* $Id$ */

/*
 * Copyright (c) 2008 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "deliver.h"
#include "fetch.h"

/*
 * This file is a bit of a mishmash, so that we can use some bits from
 * the IMAP fetching code.
 *
 * All needs to be straightened out sometime.
 */

int	 deliver_imap_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_imap_desc(struct actitem *, char *, size_t);

int	 deliver_imap_poll(struct account *, struct io *);
int	 deliver_imap_pollto(int (*)(struct account *, struct fetch_ctx *),
	     struct account *, struct io *, struct fetch_ctx *);
int	 deliver_imap_waitokay(struct account *, struct fetch_ctx *,
	     struct io *, char **);
int	 deliver_imap_waitcontinue(struct account *, struct fetch_ctx *,
	     struct io *, char **);
int	 deliver_imap_waitappend(struct account *, struct fetch_ctx *,
	     struct io *, char **);

struct deliver deliver_imap = {
	"imap",
	DELIVER_ASUSER,
	deliver_imap_deliver,
	deliver_imap_desc
};

/* Poll for data from/to server. */
int
deliver_imap_poll(struct account *a, struct io *io)
{
	char	*cause;

	switch (io_poll(io, conf.timeout, &cause)) {
	case 0:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (1);
	case -1:
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	return (0);
}

/* Poll through the IMAP fetch states until a particular one is reached. */
int
deliver_imap_pollto(int (*state)(struct account *, struct fetch_ctx *),
    struct account *a, struct io *io, struct fetch_ctx *fctx)
{
	while (state == NULL || fctx->state != state) {
		switch (fctx->state(a, fctx)) {
		case FETCH_AGAIN:
			continue;
		case FETCH_ERROR:
			return (1);
		case FETCH_EXIT:
			return (0);
		}
		if (deliver_imap_poll(a, io) != 0)
			return (1);
	}
	return (0);
}

/* Wait for okay. */
int
deliver_imap_waitokay(struct account *a, struct fetch_ctx *fctx, struct io *io,
    char **line)
{
	do {
		if (deliver_imap_poll(a, io) != 0)
			return (1);
		if (imap_getln(a, fctx, IMAP_TAGGED, line) != 0)
			return (1);
	} while (*line == NULL);

	if (!imap_okay(*line)) {
		imap_bad(a, *line);
		return (1);
	}
	return (0);
}

/* Wait for continuation. */
int
deliver_imap_waitcontinue(struct account *a, struct fetch_ctx *fctx,
    struct io *io, char **line)
{
	do {
		if (deliver_imap_poll(a, io) != 0)
			return (1);
		if (imap_getln(a, fctx, IMAP_CONTINUE, line) != 0)
			return (1);
	} while (*line == NULL);

	return (0);
}

/* Wait for append response. */
int
deliver_imap_waitappend(struct account *a, struct fetch_ctx *fctx,
    struct io *io, char **line)
{
	struct fetch_imap_data	*data = a->data;
	int			 tag;

	for (;;) {
		if (deliver_imap_poll(a, io) != 0) {
			line = NULL;
			return (IMAP_TAG_ERROR);
		}
		if (data->getln(a, fctx, line) != 0) {
			line = NULL;
			return (IMAP_TAG_ERROR);
		}
		if (*line == NULL)
			continue;

		tag = imap_tag(*line);
		if (tag != IMAP_TAG_NONE)
			break;
	}

	if (tag == IMAP_TAG_CONTINUE)
		return (IMAP_TAG_CONTINUE);
	if (tag != data->tag)
		return (IMAP_TAG_ERROR);
	return (tag);
}

int
deliver_imap_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_imap_data	*data = ti->data;
	struct io			*io;
	struct fetch_ctx		 fctx;
	struct fetch_imap_data		 fdata;
	char				*cause, *folder, *ptr, *line;
	size_t				 len, maillen;
	u_int				 total, body;

	/* Connect to the IMAP server. */
	io = connectproxy(&data->server,
	    conf.verify_certs, conf.proxy, IO_CRLF, conf.timeout, &cause);
	if (io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (DELIVER_FAILURE);
	}
	if (conf.debug > 3 && !conf.syslog)
		io->dup_fd = STDOUT_FILENO;

	/* Work out the folder name. */
	folder = replacestr(&data->folder, m->tags, m, &m->rml);
	if (folder == NULL || *folder == '\0') {
		log_warnx("%s: empty folder", a->name);
		goto error;
	}

	/* Fake up the fetch context for the fetch code. */
	memset(&fdata, 0, sizeof fdata);
	fdata.user = data->user;
	fdata.pass = data->pass;
	fdata.nocrammd5 = data->nocrammd5;
	fdata.nologin = data->nologin;
	memcpy(&fdata.server, &data->server, sizeof fdata.server);
	fdata.io = io;
	fdata.only = FETCH_ONLY_ALL;
	a->data = &fdata;
	fetch_imap_state_init(a, &fctx);
	fctx.state = imap_state_connected;
	fctx.llen = IO_LINESIZE;
	fctx.lbuf = xmalloc(fctx.llen);

	/* Use the fetch code until the select1 state is reached. */
	if (deliver_imap_pollto(imap_state_select1, a, io, &fctx) != 0)
		goto error;

retry:
	/* Send an append command. */
	if (imap_putln(a, "%u APPEND {%zu}", ++fdata.tag, strlen(folder)) != 0)
		goto error;
	switch (deliver_imap_waitappend(a, &fctx, io, &line)) {
	case IMAP_TAG_ERROR:
		if (line != NULL)
			imap_invalid(a, line);
		goto error;
	case IMAP_TAG_CONTINUE:
		break;
	default:
		if (imap_no(line) && strstr(line, "[TRYCREATE]") != NULL)
			goto try_create;
		imap_invalid(a, line);
		goto error;
	}

	/*
	 * Send the mail size, not forgetting lines are CRLF terminated. The
	 * Google IMAP server is written strangely, so send the size as if
	 * every CRLF was a CR if the server has XYZZY.
	 */
	count_lines(m, &total, &body);
	maillen = m->size + total - 1;
	if (fdata.capa & IMAP_CAPA_XYZZY) {
		log_debug2("%s: adjusting size: actual %zu", a->name, maillen);
		maillen = m->size;
	}
	if (imap_putln(a, "%s {%zu}", folder, maillen) != 0)
		goto error;
	switch (deliver_imap_waitappend(a, &fctx, io, &line)) {
	case IMAP_TAG_ERROR:
		if (line != NULL)
			imap_invalid(a, line);
		goto error;
	case IMAP_TAG_CONTINUE:
		break;
	default:
		if (imap_no(line) && strstr(line, "[TRYCREATE]") != NULL)
			goto try_create;
		imap_invalid(a, line);
		goto error;
	}

	/* Send the mail data. */
	line_init(m, &ptr, &len);
	while (ptr != NULL) {
		if (len > 1)
			io_write(io, ptr, len - 1);
		io_writeline(io, NULL);

		/* Update if necessary. */
		if (io_update(io, conf.timeout, &cause) != 1) {
			log_warnx("%s: %s", a->name, cause);
			xfree(cause);
			goto error;
		}

		line_next(m, &ptr, &len);
	}

	/* Wait for an okay from the server. */
	switch (deliver_imap_waitappend(a, &fctx, io, &line)) {
	case IMAP_TAG_ERROR:
	case IMAP_TAG_CONTINUE:
		if (line != NULL)
			imap_invalid(a, line);
		goto error;
	default:
		if (imap_okay(line))
			break;
		if (strstr(line, "[TRYCREATE]") != NULL)
			goto try_create;
		imap_invalid(a, line);
		goto error;
	}

	xfree(fctx.lbuf);
	xfree(folder);

	if (imap_putln(a, "%u LOGOUT", ++fdata.tag) != 0)
		goto error;
	if (deliver_imap_waitokay(a, &fctx, io, &line) != 0)
		goto error;

	fdata.disconnect(a);
	return (DELIVER_SUCCESS);

try_create:	/* XXX function? */
	/* Try to create the folder. */
	if (imap_putln(a, "%u CREATE {%zu}", ++fdata.tag, strlen(folder)) != 0)
		goto error;
	if (deliver_imap_waitcontinue(a, &fctx, io, &line) != 0)
		goto error;
	if (imap_putln(a, "%s", folder) != 0)
		goto error;
	if (deliver_imap_waitokay(a, &fctx, io, &line) != 0)
		goto error;
	goto retry;

error:
	io_writeline(io, "QUIT");
	io_flush(io, conf.timeout, NULL);

	xfree(fctx.lbuf);
	if (folder != NULL)
		xfree(folder);

	fdata.disconnect(a);
	return (DELIVER_FAILURE);
}

void
deliver_imap_desc(struct actitem *ti, char *buf, size_t len)
{
	struct deliver_imap_data	*data = ti->data;

	xsnprintf(buf, len, "imap%s server \"%s\" port %s folder \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->folder.str);
}
