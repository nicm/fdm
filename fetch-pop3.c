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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	pop3_init(struct account *);
int	pop3_free(struct account *);
int	pop3_connect(struct account *);
int	pop3_disconnect(struct account *);
int	pop3_poll(struct account *, u_int *);
int	pop3_fetch(struct account *, struct mail *);
int	pop3_purge(struct account *);
int	pop3_delete(struct account *);
int	pop3_keep(struct account *);
void	pop3_desc(struct account *, char *, size_t);

char   *pop3_line(struct account *, char **, size_t *);
char   *pop3_check(struct account *, char **, size_t *);

struct fetch	fetch_pop3 = { { "pop3", "pop3s" },
			       pop3_init,
			       pop3_connect,
			       pop3_poll,
			       pop3_fetch,
			       pop3_purge,
			       pop3_delete,
			       pop3_keep,
			       pop3_disconnect,
			       pop3_free,
			       pop3_desc
};

char *
pop3_line(struct account *a, char **lbuf, size_t *llen)
{
	struct pop3_data	*data = a->data;
	char			*line, *cause;

	switch (io_pollline2(data->io, &line, lbuf, llen, &cause)) {
	case 0:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (NULL);
	case -1:
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (NULL);
	}

	return (line);
}

char *
pop3_check(struct account *a, char **lbuf, size_t *llen)
{
	char	*line;

	if ((line = pop3_line(a, lbuf, llen)) == NULL)
		return (NULL);

	if (strncmp(line, "+OK", 3) != 0) {
		log_warnx("%s: unexpected data: %s", a->name, line);
		return (NULL);
	}

	return (line);
}

int
pop3_free(struct account *a)
{
	struct pop3_data	*data = a->data;
	u_int			 i;

	if (data->uid != NULL)
		xfree(data->uid);

	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++)
		xfree(ARRAY_ITEM(&data->kept, i, char *));
	ARRAY_FREE(&data->kept);

	return (0);
}

int
pop3_init(struct account *a)
{
	struct pop3_data	*data = a->data;

	ARRAY_INIT(&data->kept);

	return (0);
}

int
pop3_connect(struct account *a)
{
	struct pop3_data	*data = a->data;
	char			*lbuf, *line, *cause;
	size_t			 llen;

	data->io = connectproxy(&data->server, conf.proxy, IO_CRLF,
	    conf.timeout * 1000, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	if (pop3_check(a, &lbuf, &llen) == NULL)
		goto error;

	/* log the user in */
	io_writeline(data->io, "USER %s", data->user);
	if (pop3_check(a, &lbuf, &llen) == NULL)
		goto error;
	io_writeline(data->io, "PASS %s", data->pass);
	if (pop3_check(a, &lbuf, &llen) == NULL)
		goto error;

	/* find the number of messages */
	io_writeline(data->io, "STAT");
	if ((line = pop3_check(a, &lbuf, &llen)) == NULL)
		goto error;
	if (sscanf(line, "+OK %u %*u", &data->num) != 1) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		goto error;
	}
	data->cur = 0;

	xfree(lbuf);
	return (0);

error:
	io_writeline(data->io, "QUIT");
	io_flush(data->io, NULL);

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (1);
}

int
pop3_disconnect(struct account *a)
{
	struct pop3_data	*data = a->data;
	char			*lbuf;
	size_t			 llen;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	io_writeline(data->io, "QUIT");
	if (pop3_check(a, &lbuf, &llen) == NULL)
		goto error;

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (0);

error:
	io_writeline(data->io, "QUIT");
	io_flush(data->io, NULL);

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (1);
}

int
pop3_poll(struct account *a, u_int *n)
{
	struct pop3_data	*data = a->data;

	*n = data->num;

	return (0);
}

int
pop3_fetch(struct account *a, struct mail *m)
{
	struct pop3_data	*data = a->data;
	char			*lbuf, *line, *uid;
	size_t			 llen, size, off, len;
	u_int			 lines, n, i;
	int			 flushing;

	data->cur++;
	if (data->cur > data->num)
		return (FETCH_COMPLETE);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

restart:
	/* list the current message to get its size */
	io_writeline(data->io, "LIST %u", data->cur);
	if ((line = pop3_check(a, &lbuf, &llen)) == NULL)
		goto error;
	if (sscanf(line, "+OK %*u %zu", &size) != 1) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		goto error;
	}
	if (size == 0) {
		log_warnx("%s: zero-length message", a->name);
		goto error;
	}
	if (size > conf.max_size) {
		m->size = size;
		xfree(lbuf);
		return (FETCH_OVERSIZE);
	}

	/* find and store the UID */
	io_writeline(data->io, "UIDL %u", data->cur);
	if ((line = pop3_check(a, &lbuf, &llen)) == NULL)
		goto error;
	if (sscanf(line, "+OK %u ", &n) != 1) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		goto error;
	}
	if (n != data->cur) {
 		log_warnx("%s: unexpected message number: got %u, expected %u",
		    a->name, n, data->cur);
		goto error;
	}
	line = strchr(line, ' ');
	if (line == NULL) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		goto error;
	}
	line++;
	line = strchr(line, ' ');
	if (line == NULL) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		goto error;
	}
	if (data->uid != NULL)
		xfree(data->uid);
	data->uid = xstrdup(line);
	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
		uid = ARRAY_ITEM(&data->kept, i, char *);
		if (strcmp(data->uid, uid) == 0) {
			/* seen this message before and kept it, so skip it */
			data->cur++;
			if (data->cur > data->num) {
				xfree(lbuf);
				return (FETCH_COMPLETE);
			}
			goto restart;
		}
	}

	/* retrieve the message */
	io_writeline(data->io, "RETR %u", data->cur);
	if (pop3_check(a, &lbuf, &llen) == NULL)
		goto error;

	mail_open(m, IO_ROUND(size));
	default_tags(&m->tags, data->server.host, a);
	add_tag(&m->tags, "server", "%s", data->server.host);
	add_tag(&m->tags, "port", "%s", data->server.port);
	add_tag(&m->tags, "server_uid", "%s", data->uid);

	flushing = 0;
	off = lines = 0;
	for (;;) {
		if ((line = pop3_line(a, &lbuf, &llen)) == NULL)
			goto error;

		if (line[0] == '.' && line[1] == '.')
			line++;
		else if (line[0] == '.') {
			m->size = off;
			if (off + lines == size)
				break;

			log_warnx("%s: server lied about message size: "
			    "expected %zu, got %zu (%u lines)", a->name, size,
			    off + lines, lines);
			break;
		}

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
		if (off + lines > conf.max_size)
			flushing = 1;
	}

	xfree(lbuf);
	if (flushing)
		return (FETCH_OVERSIZE);
	return (FETCH_SUCCESS);

error:
	xfree(lbuf);
	return (FETCH_ERROR);
}

int
pop3_purge(struct account *a)
{
	if (pop3_disconnect(a) != 0)
		return (1);
	return (pop3_connect(a));
}

int
pop3_delete(struct account *a)
{
	struct pop3_data	*data = a->data;
	char			*lbuf;
	size_t			 llen;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	io_writeline(data->io, "DELE %u", data->cur);
	if (pop3_check(a, &lbuf, &llen) == NULL)
		goto error;

	xfree(lbuf);
	return (0);

error:
	xfree(lbuf);
	return (1);
}

int
pop3_keep(struct account *a)
{
	struct pop3_data	*data = a->data;

	ARRAY_ADD(&data->kept, xstrdup(data->uid), char *);

	return (0);
}

void
pop3_desc(struct account *a, char *buf, size_t len)
{
	struct pop3_data	*data = a->data;

	xsnprintf(buf, len, "pop3%s server \"%s\" port %s user \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user);
}
