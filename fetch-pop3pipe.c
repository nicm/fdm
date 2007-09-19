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
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

void	fetch_pop3pipe_fill(struct account *, struct iolist *);
void	fetch_pop3pipe_desc(struct account *, char *, size_t);

int	fetch_pop3pipe_connect(struct account *);
void	fetch_pop3pipe_disconnect(struct account *);
int	fetch_pop3pipe_putln(struct account *, const char *, va_list);
int	fetch_pop3pipe_getln(struct account *, struct fetch_ctx *, char **);

int	fetch_pop3pipe_state_init(struct account *, struct fetch_ctx *);

struct fetch fetch_pop3pipe = {
	"pop3",
	fetch_pop3pipe_state_init,

	fetch_pop3pipe_fill,
	pop3_commit,	/* from pop3-common.c */
	pop3_abort,	/* from pop3-common.c */
	pop3_total,	/* from pop3-common.c */
	fetch_pop3pipe_desc
};

/* Write line to server. */
int
fetch_pop3pipe_putln(struct account *a, const char *fmt, va_list ap)
{
	struct fetch_pop3_data	*data = a->data;

	if (data->cmd->io_in == NULL) {
		log_warnx("%s: %s", a->name, strerror(EPIPE));
		return (-1);
	}

	io_vwriteline(data->cmd->io_in, fmt, ap);
	return (0);
}

/* Get line from server. */
int
fetch_pop3pipe_getln(struct account *a, struct fetch_ctx *fctx, char **line)
{
	struct fetch_pop3_data	*data = a->data;
	char			*out, *err, *cause;

	switch (cmd_poll(
	    data->cmd, &out, &err, &fctx->lbuf, &fctx->llen, 0, &cause)) {
	case 0:
		break;
	case -1:
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	default:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (-1);
	}

	if (err != NULL) {
		log_warnx("%s: %s: %s", a->name, data->pipecmd, err);
		xfree(err);
	}
	*line = out;
	return (0);
}

/* Fill io list. */
void
fetch_pop3pipe_fill(struct account *a, struct iolist *iol)
{
	struct fetch_pop3_data	*data = a->data;

	if (data->cmd->io_in != NULL)
		ARRAY_ADD(iol, data->cmd->io_in);
	if (data->cmd->io_out != NULL)
		ARRAY_ADD(iol, data->cmd->io_out);
	if (data->cmd->io_err != NULL)
		ARRAY_ADD(iol, data->cmd->io_err);
}

/* Connect to server. */
int
fetch_pop3pipe_connect(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;
	char			*cause;

	data->cmd = cmd_start(data->pipecmd, CMD_IN|CMD_OUT, NULL, 0, &cause);
	if (data->cmd == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	}
	if (conf.debug > 3 && !conf.syslog) {
		data->cmd->io_in->dup_fd = STDOUT_FILENO;
		data->cmd->io_out->dup_fd = STDOUT_FILENO;
	}

	return (0);
}

/* Close connection. */
void
fetch_pop3pipe_disconnect(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	if (data->cmd != NULL)
		cmd_free(data->cmd);
}

/* POP3 over pipe initial state. */
int
fetch_pop3pipe_state_init(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;

	data->connect = fetch_pop3pipe_connect;
	data->getln = fetch_pop3pipe_getln;
	data->putln = fetch_pop3pipe_putln;
	data->disconnect = fetch_pop3pipe_disconnect;

	data->src = NULL;

	return (pop3_state_init(a, fctx));
}

void
fetch_pop3pipe_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_pop3_data	*data = a->data;

	if (data->user == NULL)
		xsnprintf(buf, len, "pop3 pipe \"%s\"", data->pipecmd);
	else {
		xsnprintf(buf, len,
		    "pop3 pipe \"%s\" user \"%s\"", data->pipecmd, data->user);
	}
}
