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

int	 	 imappipe_connect(struct account *);
int	 	 imappipe_disconnect(struct account *);
char		*imappipe_desc(struct account *);

int printflike2	 imappipe_putln(struct account *, const char *, ...);
char	        *imappipe_getln(struct account *, int);
void		 imappipe_flush(struct account *);

struct fetch	fetch_imappipe = { { NULL, NULL },
			       imap_init,	/* from imap-common.c */
			       imappipe_connect,
			       imap_poll,	/* from imap-common.c */
			       imap_fetch,	/* from imap-common.c */
			       imap_purge,	/* from imap-common.c */
			       imap_delete,	/* from imap-common.c */
			       imap_keep,	/* from imap-common.c */
			       imappipe_disconnect,
			       imap_free,	/* from imap-common.c */
			       imappipe_desc
};

int printflike2
imappipe_putln(struct account *a, const char *fmt, ...)
{
	struct imap_data	*data = a->data;

	va_list	ap;

	va_start(ap, fmt);
	io_vwriteline(data->cmd->io_in, fmt, ap);
	va_end(ap);

	return (0);
}

char *
imappipe_getln(struct account *a, int type)
{
	struct imap_data	*data = a->data;
	char		       **lbuf = &data->lbuf;
	size_t			*llen = &data->llen;
	char			*out, *err, *cause;
	int			 tag;

restart:
	switch (cmd_poll(data->cmd, &out, &err, lbuf, llen, &cause)) {
	case 0:
		break;
	case 1:
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (NULL);
	default:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (NULL);
	}

	if (err != NULL)
		log_warnx("%s: %s: %s", a->name, data->pipecmd, err);
	if (out == NULL)
		goto restart;

	if (type == IMAP_RAW)
		return (out);
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

	return (out);

invalid:
	log_warnx("%s: unexpected data: %s", a->name, out);
	return (NULL);
}

void
imappipe_flush(struct account *a)
{
	struct imap_data	*data = a->data;

	io_flush(data->cmd->io_in, NULL);
}

int
imappipe_connect(struct account *a)
{
	struct imap_data	*data = a->data;
	char			*cause;

	data->cmd = cmd_start(data->pipecmd, CMD_IN|CMD_OUT, NULL, 0, &cause);
	if (data->cmd == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog) {
		data->cmd->io_in->dup_fd = STDOUT_FILENO;
		data->cmd->io_out->dup_fd = STDOUT_FILENO;
	}

	data->getln = imappipe_getln;
	data->putln = imappipe_putln;
	data->flush = imappipe_flush;
	data->s = NULL;

	if (imap_login(a) != 0)
		return (1);

	if (imap_select(a) != 0) {
		imap_abort(a);
		return (1);
	}	

	return (0);
}

int
imappipe_disconnect(struct account *a)
{
	struct imap_data	*data = a->data;

	if (imap_close(a) != 0)
		goto error;
	if (imap_logout(a) != 0)
		goto error;

	cmd_free(data->cmd);

	return (0);

error:
	imap_abort(a);

	cmd_free(data->cmd);

	return (1);
}

char *
imappipe_desc(struct account *a)
{
	struct imap_data	*data = a->data;
	char			*s;

	if (data->user != NULL) {
		xasprintf(&s, "imap pipe \"%s\" user \"%s\" folder \"%s\"",
		    data->pipecmd, data->user, data->folder);
	} else {
		xasprintf(&s, "imap pipe \"%s\" folder \"%s\"", data->pipecmd,
		    data->folder);
	}
	return (s);
}
