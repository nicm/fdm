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

int	nntp_connect(struct account *);
int	nntp_disconnect(struct account *);
int	nntp_fetch(struct account *, struct mail *);
int	nntp_delete(struct account *);
int	nntp_keep(struct account *);
void	nntp_error(struct account *);
char   *nntp_desc(struct account *);

int	nntp_code(char *);

struct fetch	fetch_nntp = { { "nntp", NULL },
			       nntp_connect,
			       NULL,
			       nntp_fetch,
			       nntp_delete,
			       nntp_keep,
			       nntp_error,
			       nntp_disconnect,
			       nntp_desc
};

int
nntp_connect(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*cause;
	u_int			 n;

	data->io = connectproxy(&data->server, conf.proxy, IO_CRLF, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	n = cache_compact(data->cache, data->expiry);
	log_debug("%s: expired %u entries from cache", a->name, n);
	
	data->state = NNTP_CONNECTING;

	return (0);
}

int
nntp_disconnect(struct account *a)
{
	struct nntp_data	*data = a->data;

	io_close(data->io);
	io_free(data->io);

	cache_close(data->cache);

	return (0);
}

void
nntp_error(struct account *a)
{
	struct nntp_data	*data = a->data;

	if (data->key != NULL)
		xfree(data->key);

	io_writeline(data->io, "QUIT");
	io_flush(data->io, NULL);
}

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

int
nntp_fetch(struct account *a, struct mail *m)
{
	struct nntp_data	*data = a->data;
	int		 	 code, res, flushing;
	char			*line, *cause, *ptr, *ptr2, *lbuf;
	size_t			 off = 0, len, llen;
	u_int			 lines = 0, n;

	if (m != NULL) {
		m->data = NULL;
		m->s = xstrdup(data->group);
	}

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	flushing = 0;
	line = cause = NULL;
	do {
		switch (io_poll(data->io, &cause)) {
		case -1:
			goto error;
		case 0:
			cause = xstrdup("connection unexpectedly closed");
			goto error;
		}

		res = -1;
		do {
			line = io_readline2(data->io, &lbuf, &llen);
			if (line == NULL)
				break;
			code = nntp_code(line);

			switch (data->state) {
			case NNTP_CONNECTING:
				if (code >= 100 && code <= 199)
					break;
				if (code != 200)
					goto error;

				data->state = NNTP_GROUP;
				io_writeline(data->io, "GROUP %s",
				    data->group);
				break;
			case NNTP_GROUP:
				if (code >= 100 && code <= 199)
					break;
				if (code != 211)
					goto error;

				if (sscanf(line, "211 %*u %u %*u", &n) != 1)
					goto error;

				data->state = NNTP_NEXT;
				io_writeline(data->io, "STAT %u", n);
				break;
			case NNTP_NEXT:
				if (code >= 100 && code <= 199)
					break;
				if (code == 421) {
					data->state = NNTP_QUIT;
					io_writeline(data->io, "QUIT");
					break;
				}
				if (code == 423 || code == 430) {
					data->state = NNTP_NEXT;
					io_writeline(data->io, "NEXT");
					break;					
				}
				if (code != 223)
					goto error;

				ptr = strchr(line, '<');
				if (ptr == NULL)
					goto error;
				ptr2 = strchr(ptr, '>');
				if (ptr2 == NULL)
					goto error;
				ptr++;

				len = ptr2 - ptr;
				data->key = xmalloc(len + 1);
				memcpy(data->key, ptr, len);
				data->key[len] = '\0';

				if (cache_contains(data->cache, data->key)) {
					log_debug3("%s: found in cache: %s",
					    a->name, data->key);

					xfree(data->key);
					data->key = NULL;

					io_writeline(data->io, "NEXT");
					break;
				}
				log_debug2("%s: new: %s", a->name, data->key);
				
				off = lines = 0;
				init_mail(m, IO_BLOCKSIZE);

				data->state = NNTP_ARTICLE;
				io_writeline(data->io, "ARTICLE");
				break;
			case NNTP_ARTICLE:
				if (code >= 100 && code <= 199)
					break;
				if (code == 423 || code == 430) {
					xfree(data->key);
					data->key = NULL;

					data->state = NNTP_NEXT;
					io_writeline(data->io, "NEXT");
					break;					
				}
				if (code != 220)
					goto error;

				data->state = NNTP_LINE;
				break;
			case NNTP_LINE:
				ptr = line;
				if (ptr[0] == '.' && ptr[1] != '\0')
					ptr++;
				else if (ptr[0] == '.') {
					m->size = off;

					if (flushing)
						res = FETCH_OVERSIZE;
					else
						res = FETCH_SUCCESS;
					data->state = NNTP_NEXT;
					io_writeline(data->io, "NEXT");
					break;
				}

				len = strlen(ptr);
				if (len == 0 && m->body == -1)
					m->body = off + 1;

				if (flushing) {
					off += len + 1;
					break;
				}

				resize_mail(m, off + len + 1);

				if (len > 0)
					memcpy(m->data + off, ptr, len);
				/* append an LF */
				m->data[off + len] = '\n';
				lines++;
				off += len + 1;

				if (off + lines > conf.max_size)
					flushing = 1;
				break;
			case NNTP_QUIT
				if (code >= 100 && code <= 199)
					break;
				if (code != 205)
					goto error;

				res = FETCH_COMPLETE;
				break;
			}
		} while (res == -1);
	} while (res == -1);

	xfree(lbuf);
	io_flush(data->io, NULL);
	return (res);

error:
	if (cause != NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
	} else
		log_warnx("%s: unexpected response: %s", a->name, line);

	xfree(lbuf);
	io_flush(data->io, NULL);
	return (FETCH_ERROR);
}

int
nntp_delete(struct account *a)
{
	struct nntp_data	*data = a->data;

	cache_add(data->cache, data->key);

	xfree(data->key);
		
	return (0);
}

int
nntp_keep(struct account *a)
{
	struct nntp_data	*data = a->data;

	xfree(data->key);

	return (0);
}

char *
nntp_desc(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*s;

	xasprintf(&s, "nntp server \"%s\" port %s group \"%s\" cache \"%s\"",
	    data->server.host, data->server.port, data->group,
	    data->cache->path);
	return (s);
}
