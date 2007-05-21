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

int	fetch_imappipe_connect(struct account *);
void	fetch_imappipe_fill(struct account *, struct io **, u_int *n);
int	fetch_imappipe_disconnect(struct account *, int);
void	fetch_imappipe_desc(struct account *, char *, size_t);

int	fetch_imappipe_putln(struct account *, const char *, va_list);
int	fetch_imappipe_getln(struct account *, char **);
int	fetch_imappipe_closed(struct account *);
void	fetch_imappipe_close(struct account *);

struct fetch fetch_imappipe = {
	"imappipe",
	fetch_imappipe_connect,
	fetch_imappipe_fill,
	imap_total,	/* from imap-common.c */
	imap_completed,	/* from imap-common.c */
	imap_closed,	/* from imap-common.c */
	imap_fetch,	/* from imap-common.c */
	imap_poll,	/* from imap-common.c */
	imap_purge,	/* from imap-common.c */
	imap_close,	/* from imap-common.c */
	fetch_imappipe_disconnect,
	fetch_imappipe_desc,
};

/* Write line to server. */
int
fetch_imappipe_putln(struct account *a, const char *fmt, va_list ap)
{
	struct fetch_imap_data	*data = a->data;

	io_vwriteline(data->cmd->io_in, fmt, ap);

	return (0);
}

/* Get line from server. */ 
int
fetch_imappipe_getln(struct account *a, char **line)
{
	struct fetch_imap_data	*data = a->data;
	char			*out, *err, *cause;
	int			 n;

	data->cmd->timeout = 0;
	n = cmd_poll(data->cmd, &out, &err, &data->lbuf, &data->llen, &cause);
	switch (n) {
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

/* Return if connection is closed. */
int
fetch_imappipe_closed(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	return (data->cmd == NULL);
}

/* Close connection. */
void
fetch_imappipe_close(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	cmd_free(data->cmd);
	data->cmd = NULL;
}

/* Connect to server and set up callback functions. */
int
fetch_imappipe_connect(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*cause;

	data->cmd = 
	    cmd_start(data->pipecmd, CMD_IN|CMD_OUT, 0, NULL, 0, &cause);
	if (data->cmd == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	}
	if (conf.debug > 3 && !conf.syslog) {
		data->cmd->io_in->dup_fd = STDOUT_FILENO;
		data->cmd->io_out->dup_fd = STDOUT_FILENO;
	}

	data->getln = fetch_imappipe_getln;
	data->putln = fetch_imappipe_putln;
	data->closed = fetch_imappipe_closed;
	data->close = fetch_imappipe_close;
	data->src = NULL;

	return (imap_connect(a));
}

/* Fill io list. */
void
fetch_imappipe_fill(struct account *a, struct io **iop, u_int *n)
{
	struct fetch_imap_data	*data = a->data;

	if (data->cmd->io_in != NULL)
		iop[(*n)++] = data->cmd->io_in;
	if (data->cmd->io_out != NULL)
		iop[(*n)++] = data->cmd->io_out;
	if (data->cmd->io_err != NULL)
		iop[(*n)++] = data->cmd->io_err;
}

/* Close connection and clean up. */
int
fetch_imappipe_disconnect(struct account *a, int aborted)
{
	struct fetch_imap_data	*data = a->data;

	if (data->cmd != NULL)
		cmd_free(data->cmd);

	return (imap_disconnect(a, aborted));
}

void
fetch_imappipe_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_imap_data	*data = a->data;

	if (data->user == NULL) {
		xsnprintf(buf, len, "imap pipe \"%s\" folder \"%s\"",
		    data->pipecmd, data->folder);
	} else {
		xsnprintf(buf, len,
		    "imap pipe \"%s\" user \"%s\" folder \"%s\"",
		    data->pipecmd, data->user, data->folder);
	}
}
