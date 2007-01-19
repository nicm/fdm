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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	 imap_init(struct account *);
int	 imap_connect(struct account *);
int	 imap_disconnect(struct account *);
int	 imap_poll(struct account *, u_int *);
int	 imap_fetch(struct account *, struct mail *);
int	 imap_purge(struct account *);
int	 imap_delete(struct account *);
int	 imap_keep(struct account *);
int	 imap_free(struct account *);
char	*imap_desc(struct account *);

int	 imap_tag(char *);
int	 imap_okay(struct account *, char *, const char *);
char	*imap_line(struct account *, char **, size_t *, const char *);
char 	*imap_check_none(struct account *, char **, size_t *, const char *);
char 	*imap_check_continue(struct account *, char **, size_t *, const char *);
char 	*imap_check_normal(struct account *, char **, size_t *, const char *);

#define IMAP_TAG_NONE -1
#define IMAP_TAG_CONTINUE -2
#define IMAP_TAG_ERROR -3

struct fetch	fetch_imap = { { "imap", "imaps" },
			       imap_init,
			       imap_connect,
			       imap_poll,
			       imap_fetch,
			       imap_purge,
			       imap_delete,
			       imap_keep,
			       imap_disconnect,
			       imap_free,
			       imap_desc
};

int
imap_tag(char *line)
{
	long	 	 tag;
	const char	*errstr;
	char		*ptr;

	if (line[0] == '*' && line[1] == ' ')
		return (IMAP_TAG_NONE);
	if (line[0] == '+')
		return (IMAP_TAG_CONTINUE);

	if ((ptr = strchr(line, ' ')) == NULL)
		return (IMAP_TAG_ERROR);
	*ptr = '\0';

	tag = strtonum(line, 0, INT_MAX, &errstr);
	*ptr = ' ';
	if (errstr != NULL)
		return (IMAP_TAG_ERROR);

	return (tag);
}

int
imap_okay(struct account *a, char *line, const char *s)
{
	char	*ptr;

	ptr = strchr(line, ' ');
	if (ptr == NULL || strncmp(ptr + 1, "OK ", 3) != 0) {
		log_warnx("%s: %s: unexpected data: %s", a->name, s, line);
		return (0);
	}

	return (1);
}

char *
imap_line(struct account *a, char **lbuf, size_t *llen, const char *s)
{
	struct imap_data	*data = a->data;
	char			*line, *cause;

	switch (io_pollline2(data->io, &line, lbuf, llen, &cause)) {
	case 0:
		log_warnx("%s: %s: connection unexpectedly closed", a->name, s);
		return (NULL);
	case -1:
		log_warnx("%s: %s: %s", a->name, s, cause);
		xfree(cause);
		return (NULL);
	}

	return (line);
}

char *
imap_check_none(struct account *a, char **lbuf, size_t *llen, const char *s)
{
	char	*line;

	if ((line = imap_line(a, lbuf, llen, s)) == NULL)
		return (NULL);

	if (imap_tag(line) == IMAP_TAG_NONE)
		return (line);

	log_warnx("%s: %s: unexpected data: %s", a->name, s, line);
	return (NULL);
}

char *
imap_check_continue(struct account *a, char **lbuf, size_t *llen, const char *s)
{
	char	*line;

restart:
	if ((line = imap_line(a, lbuf, llen, s)) == NULL)
		return (NULL);

	switch (imap_tag(line)) {
	case IMAP_TAG_NONE:
		goto restart;
	case IMAP_TAG_CONTINUE:
		return (line);
	}

	log_warnx("%s: %s: unexpected data: %s", a->name, s, line);
	return (NULL);
}

char *
imap_check_normal(struct account *a, char **lbuf, size_t *llen, const char *s)
{
	struct imap_data	*data = a->data;
	char			*line;
	long	 		 tag;

restart:
	if ((line = imap_line(a, lbuf, llen, s)) == NULL)
		return (NULL);

	tag = imap_tag(line);
	switch (tag) {
	case IMAP_TAG_NONE:
		goto restart;
	case IMAP_TAG_CONTINUE:
		break;
	default:
		if (data->tag != tag)
			break;
		return (line);
	}

	log_warnx("%s: %s: unexpected data: %s", a->name, s, line);
	return (NULL);
}

int
imap_init(struct account *a)
{
	struct imap_data	*data = a->data;

	ARRAY_INIT(&data->kept);

	return (0);
}

int
imap_free(struct account *a)
{
	struct imap_data	*data = a->data;

	ARRAY_FREE(&data->kept);

	return (0);
}

int
imap_connect(struct account *a)
{
	struct imap_data	*data = a->data;
	struct io		*io;
	char			*lbuf, *line, *cause;
	size_t			 llen;

	data->io = connectproxy(&data->server, conf.proxy, IO_CRLF, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;
	io = data->io;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	/* log the user in */
	if (imap_check_none(a, &lbuf, &llen, "CONNECT") == NULL)
		goto error;
	io_writeline(io, "%u LOGIN {%zu}", ++data->tag, strlen(data->user));
	if (imap_check_continue(a, &lbuf, &llen, "LOGIN") == NULL)
		goto error;
	io_writeline(io, "%s {%zu}", data->user, strlen(data->pass));
	if (imap_check_continue(a, &lbuf, &llen, "LOGIN") == NULL)
		goto error;
	io_writeline(io, "%s", data->pass);
	if ((line = imap_check_normal(a, &lbuf, &llen, "LOGIN")) == NULL)
		goto error;
	if (!imap_okay(a, line, "LOGIN"))
		goto error;

	/* select the folder */
	io_writeline(data->io, "%u SELECT %s", ++data->tag, data->folder);
	do {
		line = imap_check_none(a, &lbuf, &llen, "SELECT");
		if (line == NULL)
			goto error;
	} while (sscanf(line, "* %u EXISTS", &data->num) != 1);
	if ((line = imap_check_normal(a, &lbuf, &llen, "SELECT")) == NULL)
		goto error;
	if (!imap_okay(a, line, "SELECT"))
		goto error;
	data->cur = 0;

	xfree(lbuf);
	return (0);

error:
	io_writeline(data->io, "%u LOGOUT", ++data->tag);
	io_flush(data->io, NULL);

	xfree(lbuf);
	return (1);
}

int
imap_disconnect(struct account *a)
{
	struct imap_data	*data = a->data;
	char			*lbuf, *line;
	size_t			 llen;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	io_writeline(data->io, "%u CLOSE", ++data->tag);
	if ((line = imap_check_normal(a, &lbuf, &llen, "CLOSE")) == NULL)
		goto error;
	if (!imap_okay(a, line, "CLOSE"))
		goto error;
	io_writeline(data->io, "%u LOGOUT", ++data->tag);
	if ((line = imap_check_normal(a, &lbuf, &llen, "LOGOUT")) == NULL)
		goto error;
	if (!imap_okay(a, line, "LOGOUT"))
		goto error;

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (0);

error:
	io_writeline(data->io, "%u LOGOUT", ++data->tag);
	io_flush(data->io, NULL);

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (1);
}

int
imap_poll(struct account *a, u_int *n)
{
	struct imap_data	*data = a->data;

	*n = data->num;
	return (0);
}

int
imap_fetch(struct account *a, struct mail *m)
{
	struct imap_data	*data = a->data;
	char			*lbuf, *line;
	size_t			 llen, size, off, len;
	u_int			 lines, n, i;
	int			 flushing;

	data->cur++;
	if (data->cur > data->num)
		return (FETCH_COMPLETE);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

restart:
	/* find message UID */
	io_writeline(data->io, "%u FETCH %u UID", ++data->tag, data->cur);
	if ((line = imap_check_none(a, &lbuf, &llen, "FETCH")) == NULL)
		goto error;
	if (sscanf(line, "* %u FETCH (UID %u)", &n, &data->uid) != 2) {
 		log_warnx("%s: FETCH: invalid response: %s", a->name, line);
		goto error;
	}
	if ((line = imap_check_normal(a, &lbuf, &llen, "FETCH")) == NULL)
		goto error;
	if (!imap_okay(a, line, "FETCH"))
		goto error;
	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
		if (ARRAY_ITEM(&data->kept, i, u_int) == data->uid) {
			/* seen this message before and kept it, so skip it */
			data->cur++;
			if (data->cur > data->num) {
				xfree(lbuf);
				return (FETCH_COMPLETE);
			}
			goto restart;
		}
	}

	io_writeline(data->io, "%u FETCH %u BODY[]", ++data->tag, data->cur);
	if ((line = imap_check_none(a, &lbuf, &llen, "FETCH")) == NULL)
		goto error;
	if (sscanf(line, "* %u FETCH (BODY[] {%zu}", &n, &size) != 2) {
 		log_warnx("%s: FETCH: invalid response: %s", a->name, line);
		goto error;
	}
	if (n != data->cur) {
		log_warnx("%s: FETCH: incorrect message index", a->name);
		goto error;
	}
	if (size == 0) {
		log_warnx("%s: FETCH: zero-length message", a->name);
		goto error;
	}

	mail_open(m, IO_ROUND(size));
	m->s = xstrdup(data->server.host);

	/* read the message */
	flushing = 0;
	if (size > conf.max_size)
		flushing = 1;
	off = lines = 0;
	for (;;) {
		if ((line = imap_line(a, &lbuf, &llen, "FETCH")) == NULL)
			goto error;

		len = strlen(line);
		if (len == 0 && m->body == -1)
			m->body = off + 1;

		if (!flushing) {
			resize_mail(m, off + len + 1);

			if (len > 0)
				memcpy(m->data + off, line, len);
			m->data[off + len] = '\n';
		}

		lines++;
		off += len + 1;
		if (off + lines >= size)
			break;
	}
	if ((line = imap_line(a, &lbuf, &llen, "FETCH")) == NULL)
		goto error;
	if (strcmp(line, ")") != 0) {
 		log_warnx("%s: FETCH: invalid response: %s", a->name, line);
		goto error;
	}

	if ((line = imap_check_normal(a, &lbuf, &llen, "FETCH")) == NULL)
		goto error;
	if (!imap_okay(a, line, "FETCH"))
		goto error;
	if (off + lines != size) {
 		log_warnx("%s: FETCH: received too much data", a->name);
		goto error;
	}
	m->size = off;

	xfree(lbuf);
	if (flushing)
		return (FETCH_OVERSIZE);
	return (FETCH_SUCCESS);

error:
	xfree(lbuf);
	return (FETCH_ERROR);
}

int
imap_purge(struct account *a)
{
	struct imap_data	*data = a->data;
	char			*lbuf, *line;
	size_t			 llen;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	/* expunge deleted messages */
	io_writeline(data->io, "%u EXPUNGE", ++data->tag);
	if ((line = imap_check_normal(a, &lbuf, &llen, "EXPUNGE")) == NULL)
		goto error;
	if (!imap_okay(a, line, "EXPUNGE"))
		goto error;

	/* reselect the folder */
	io_writeline(data->io, "%u SELECT %s", ++data->tag, data->folder);
	do {
		line = imap_check_none(a, &lbuf, &llen, "SELECT");
		if (line == NULL)
			goto error;
	} while (sscanf(line, "* %u EXISTS", &data->num) != 1);
	if ((line = imap_check_normal(a, &lbuf, &llen, "SELECT")) == NULL)
		goto error;
	if (!imap_okay(a, line, "SELECT"))
		goto error;
	data->cur = 0;

	xfree(lbuf);
	return (0);

error:
	xfree(lbuf);
	return (1);
}

int
imap_delete(struct account *a)
{
	struct imap_data	*data = a->data;
	char			*lbuf, *line;
	size_t			 llen;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	io_writeline(data->io, "%u STORE %u +FLAGS \\Deleted", ++data->tag,
	    data->cur);
	if ((line = imap_check_normal(a, &lbuf, &llen, "STORE")) == NULL)
		goto error;
	if (!imap_okay(a, line, "STORE"))
		goto error;

	xfree(lbuf);
	return (0);

error:
	xfree(lbuf);
	return (1);
}

int
imap_keep(struct account *a)
{
	struct imap_data	*data = a->data;

	ARRAY_ADD(&data->kept, data->uid, u_int);

	return (0);
}

char *
imap_desc(struct account *a)
{
	struct imap_data	*data = a->data;
	char			*s;

	xasprintf(&s, "imap%s server \"%s\" port %s user \"%s\" folder \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user, data->folder);
	return (s);
}
