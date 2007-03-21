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

int	 	 fetch_imappipe_start(struct account *);
void	 	 fetch_imappipe_fill(struct account *, struct io **, u_int *n);
int	 	 fetch_imappipe_finish(struct account *, int);
void		 fetch_imappipe_desc(struct account *, char *, size_t);

int printflike2	 fetch_imappipe_putln(struct account *, const char *, ...);
int		 fetch_imappipe_getln(struct account *, int, char **, int);
void		 fetch_imappipe_flush(struct account *);

struct fetch fetch_imappipe = {
	"imappipe",
	{ NULL, NULL },
	fetch_imappipe_start,
	fetch_imappipe_fill,
	imap_poll,	/* from imap-common.c */
	imap_fetch,	/* from imap-common.c */
	imap_purge,	/* from imap-common.c */
	imap_done,	/* from imap-common.c */
	fetch_imappipe_finish,
	fetch_imappipe_desc,
};

int printflike2
fetch_imappipe_putln(struct account *a, const char *fmt, ...)
{
	struct fetch_imap_data	*data = a->data;

	va_list	ap;

	va_start(ap, fmt);
	io_vwriteline(data->cmd->io_in, fmt, ap);
	va_end(ap);

	return (0);
}

int
fetch_imappipe_getln(struct account *a, int type, char **line, int block)
{
	struct fetch_imap_data	*data = a->data;
	char		       **lbuf = &data->lbuf;
	size_t			*llen = &data->llen;
	char			*out, *err, *cause;
	int			 tag;

	data->cmd->timeout = conf.timeout;
	if (!block)
		data->cmd->timeout = 0;

restart:
	switch (cmd_poll(data->cmd, &out, &err, lbuf, llen, &cause)) {
	case 0:
		break;
	case 1:
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	default:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (-1);
	}

	if (err != NULL)
		log_warnx("%s: %s: %s", a->name, data->pipecmd, err);
	if (out == NULL) {
		if (!block)
			return (1);
		goto restart;
	}
	*line = out;

	if (type == IMAP_RAW)
		return (0);
	tag = imap_tag(out);
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
	log_warnx("%s: unexpected data: %s", a->name, out);
	return (-1);
}

void
fetch_imappipe_flush(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	io_flush(data->cmd->io_in, NULL);
}

int
fetch_imappipe_start(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*cause;

	if (imap_start(a) != FETCH_SUCCESS)
		return (FETCH_ERROR);

	data->cmd = cmd_start(data->pipecmd, CMD_IN|CMD_OUT, conf.timeout,
	    NULL, 0, &cause);
	if (data->cmd == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}
	if (conf.debug > 3 && !conf.syslog) {
		data->cmd->io_in->dup_fd = STDOUT_FILENO;
		data->cmd->io_out->dup_fd = STDOUT_FILENO;
	}

	data->getln = fetch_imappipe_getln;
	data->putln = fetch_imappipe_putln;
	data->flush = fetch_imappipe_flush;
	data->src = NULL;

	if (imap_login(a) != 0)
		return (FETCH_ERROR);

	if (imap_select(a) != 0) {
		imap_abort(a);
		return (FETCH_ERROR);
	}

	return (FETCH_SUCCESS);
}

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

int
fetch_imappipe_finish(struct account *a, int aborted)
{
	struct fetch_imap_data	*data = a->data;

	if (data->cmd != NULL) {
		if (aborted)
			imap_abort(a);
		else if (imap_close(a) != 0 || imap_logout(a) != 0) {
			imap_abort(a);
			goto error;
		}

		if (data->cmd != NULL)
			cmd_free(data->cmd);
	}

	return (imap_finish(a));

error:
	if (data->cmd != NULL)
		cmd_free(data->cmd);

	imap_finish(a);
	return (FETCH_ERROR);
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
