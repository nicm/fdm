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

int	nntp_init(struct account *);
int	nntp_free(struct account *);
int	nntp_connect(struct account *);
int	nntp_disconnect(struct account *);
int	nntp_fetch(struct account *, struct mail *);
int	nntp_delete(struct account *);
int	nntp_keep(struct account *);
char   *nntp_desc(struct account *);

int	nntp_code(char *);
char   *nntp_line(struct account *, char **, size_t *, const char *);
char   *nntp_check(struct account *, char **, size_t *, const char *, u_int *);
int	nntp_is(struct account *, char *, const char *, u_int, u_int);
int	nntp_group(struct account *, char **, size_t *);

struct fetch	fetch_nntp = { { "nntp", NULL },
			       nntp_init,
			       nntp_connect,
			       NULL,
			       nntp_fetch,
			       NULL,
			       nntp_delete,
			       nntp_keep,
			       nntp_disconnect,
			       nntp_free,
			       nntp_desc
};

int
nntp_code(char *line)
{
	char		 ch;
	const char	*errstr;
	int	 	 n;
	size_t		 len;

	len = strspn(line, "0123456789");
	if (len == 0)
		return (-1);
	ch = line[len];
	line[len] = '\0';

	n = strtonum(line, 100, 999, &errstr);
	line[len] = ch;
	if (errstr != NULL)
		return (-1);

	return (n);
}

char *
nntp_line(struct account *a, char **lbuf, size_t *llen, const char *s)
{
	struct nntp_data	*data = a->data;
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
nntp_check(struct account *a, char **lbuf, size_t *llen, const char *s,
    u_int *code)
{
	char	*line;

restart:
	if ((line = nntp_line(a, lbuf, llen, s)) == NULL)
		return (NULL);

	*code = nntp_code(line);
	if (*code >= 100 && *code <= 199)
		goto restart;

	return (line);
}

int
nntp_is(struct account *a, char *line, const char *s, u_int code, u_int n)
{
	if (code != n) {
		log_warnx("%s: %s: unexpected data: %s", a->name, s, line);
		return (0);
	}
	return (1);
}

int
nntp_group(struct account *a, char **lbuf, size_t *llen)
{
	struct nntp_data	*data = a->data;
	char			*line, *group;
	u_int			 code, n;

	group = ARRAY_ITEM(data->groups, data->group, char *);
	io_writeline(data->io, "GROUP %s", group);

	if ((line = nntp_check(a, lbuf, llen, "GROUP", &code)) == NULL)
		return (1);
	if (!nntp_is(a, line, "GROUP", code, 211))
		return (1);
	if (sscanf(line, "211 %*u %u %*u", &n) != 1) {
		log_warnx("%s: GROUP: invalid response: %s", a->name, line);
		return (1);
	}
	if (n > UINT_MAX) {
		log_warnx("%s: GROUP: bad message index: %s", a->name, line);
		return (1);
	}
	data->first = n;

	return (0);
}

int
nntp_init(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*cause;

	data->cache = cache_open(data->path, &cause);
	if (data->cache == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	data->group = 0;

	return (0);
}

int
nntp_free(struct account *a)
{
	struct nntp_data	*data = a->data;

	if (data->key != NULL)
		xfree(data->key);

	return (0);
}

int
nntp_connect(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*lbuf, *line, *cause;
	size_t			 llen;
	u_int			 n, total, code;

	data->io = connectproxy(&data->server, conf.proxy, IO_CRLF, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	n = cache_compact(data->cache, data->expiry, &total);
	log_debug("%s: cache has %u entries", a->name, total);
	log_debug("%s: expired %u entries", a->name, n);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	if ((line = nntp_check(a, &lbuf, &llen, "CONNECT", &code)) == NULL)
		goto error;
	if (!nntp_is(a, line, "CONNECT", code, 200))
		goto error;

	if (nntp_group(a, &lbuf, &llen) != 0)
		goto error;

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
nntp_disconnect(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*lbuf, *line;
	size_t			 llen;
	u_int			 code;

	cache_close(data->cache);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	io_writeline(data->io, "QUIT");
	if ((line = nntp_check(a, &lbuf, &llen, "QUIT", &code)) == NULL)
		goto error;
	if (!nntp_is(a, line, "QUIT", code, 205))
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
nntp_fetch(struct account *a, struct mail *m)
{
	struct nntp_data	*data = a->data;
	char			*lbuf, *line, *ptr, *ptr2;
	size_t			 llen, off, len;
	u_int			 lines, code;
	int			 flushing;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

restart:
	if (data->first > 0) {
		io_writeline(data->io, "STAT %llu", data->first);
		data->first = -1;
	} else
		io_writeline(data->io, "NEXT");
	if ((line = nntp_check(a, &lbuf, &llen, "NEXT", &code)) == NULL)
		goto error;
	if (code == 421) {
		data->group++;
		if (data->group == ARRAY_LENGTH(data->groups)) {
			xfree(lbuf);
			return (FETCH_COMPLETE);
		}
		if (nntp_group(a, &lbuf, &llen) != 0)
			goto error;
		goto restart;
	}
	if (code == 423 || code == 430) {
		io_writeline(data->io, "NEXT");
		goto restart;
	}
	if (!nntp_is(a, line, "NEXT", code, 223))
		goto error;

	/* find message-id */
	ptr = strchr(line, '<');
	ptr2 = NULL;
	if (ptr != NULL)
		ptr2 = strchr(ptr, '>');
	if (ptr == NULL || ptr2 == NULL) {
		log_warnx("%s: NEXT: bad response: %s", a->name, line);
		goto restart;
	}

	ptr++;
	len = ptr2 - ptr;
	data->key = xmalloc(len + 1);
	memcpy(data->key, ptr, len);
	data->key[len] = '\0';

	if (cache_contains(data->cache, data->key)) {
		log_debug3("%s: found in cache: %s", a->name, data->key);
		cache_update(data->cache, data->key);

		xfree(data->key);
		data->key = NULL;
		goto restart;
	}
	log_debug2("%s: new: %s", a->name, data->key);

	/* retrieve the article */
	io_writeline(data->io, "ARTICLE");
	if ((line = nntp_check(a, &lbuf, &llen, "ARTICLE", &code)) == NULL)
		goto error;
	if (code == 423 || code == 430) {
		xfree(data->key);
		data->key = NULL;
		goto restart;
	}
	if (!nntp_is(a, line, "ARTICLE", code, 220))
		goto error;

	mail_open(m, IO_BLOCKSIZE);
	m->s = xstrdup(ARRAY_ITEM(data->groups, data->group, char *));

	flushing = 0;
	off = lines = 0;
	for (;;) {
		if ((line = nntp_line(a, &lbuf, &llen, "ARTICLE")) == NULL)
			goto error;

		if (line[0] == '.' && line[1] == '.')
			line++;
		else if (line[0] == '.') {
			m->size = off;
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
nntp_delete(struct account *a)
{
	struct nntp_data	*data = a->data;

	cache_add(data->cache, data->key);

	xfree(data->key);
	data->key = NULL;

	return (0);
}

int
nntp_keep(struct account *a)
{
	struct nntp_data	*data = a->data;

	xfree(data->key);
	data->key = NULL;

	return (0);
}

char *
nntp_desc(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*s, *groups;

	groups = fmt_strings("groups ", data->groups);
	xasprintf(&s, "nntp server \"%s\" port %s %s cache \"%s\" expiry %lld "
	    "seconds", data->server.host, data->server.port, groups,
	    data->path, data->expiry);
	xfree(groups);
	return (s);
}
