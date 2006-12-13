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
	u_int 			 i;

	data->io = connectproxy(&data->server, conf.proxy, IO_CRLF, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = NNTP_CONNECTING;

	if (cache_load(data->cache, &cause) != 0) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	log_debug("%s: cache has %u entries", a->name,
	    ARRAY_LENGTH(&data->cache->list));
	for (i = 0; i < ARRAY_LENGTH(&data->cache->list); i++) {
		log_debug3("%s: %u: %s", a->name, i, data->cache->data + 
		    (&ARRAY_ITEM(&data->cache->list, i, struct cacheent))->off);
	}

	return (0);
}

int
nntp_disconnect(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*cause;

	io_close(data->io);
	io_free(data->io);

	if (cache_save(data->cache, &cause) != 0) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	return (0);
}

void
nntp_error(struct account *a)
{
	struct nntp_data	*data = a->data;

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
		m->s = xstrdup(data->server.host);
	}

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	/*
	 * The main loops rely on the server prompting us with data in order
	 * to switch state. NNTP doesn't do this after it sends an article,
	 * and there is no noop command to use in delete/keep to force it to
	 * do so. So, the DONE state is handled outside the loop. Always
	 * relying on the server to provide the kicks to us is a bit horrible
	 * and needs to be rethought, both here and in fetch-{pop3,imap}.c and
	 * deliver-smtp.c. 
	 */
	if (data->state == NNTP_DONE) {
		data->cur++;
		if (data->cur > data->last) {
			data->state = NNTP_QUIT;
			io_writeline(data->io, "QUIT");
		} else {
			data->state = NNTP_STAT;
			io_writeline(data->io, "STAT %u", data->cur);
		}
	}

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

				if (sscanf(line, "211 %*u %u %u", &data->cur,
				    &data->last) != 2)
					goto error;

				data->state = NNTP_STAT;
				io_writeline(data->io, "STAT %u", data->cur);
				break;
			case NNTP_STAT:
				if (code >= 100 && code <= 199)
					break;
				if (code == 423 || code == 430) {
					data->cur++;
					if (data->cur > data->last) {
						data->state = NNTP_QUIT;
						io_writeline(data->io, "QUIT");
						break;
					}
					data->state = NNTP_STAT;
					io_writeline(data->io, "STAT %u",
					    data->cur);
					break;					
				}
				if (code != 223)
					goto error;

				if (sscanf(line, "223 %u <", &n) != 1)
					goto error;
				if (n != data->cur)
					goto error;

				ptr = strchr(line, '<');
				if (ptr == NULL)
					goto error;
				ptr++;
				ptr2 = strchr(ptr, '>');
				if (ptr2 == NULL)
					goto error;
				data->key = xmalloc((ptr2 - ptr) + 1);
				memcpy(data->key, ptr, ptr2 - ptr);
				data->key[ptr2 - ptr] = '\0';

				if (cache_contains(data->cache, data->key)) {
					log_debug2("%s: found in cache: %s",
					    a->name, data->key);

					xfree(data->key);
					data->key = NULL;

					data->cur++;
					if (data->cur > data->last) {
						res = FETCH_COMPLETE;
						break;
					}

					data->state = NNTP_STAT;
					io_writeline(data->io, "STAT %u",
					    data->cur);
					break;
				}
				log_debug2("%s: new: %s", a->name, data->key);
				
				off = lines = 0;
				init_mail(m, IO_BLOCKSIZE);

				data->state = NNTP_ARTICLE;
				io_writeline(data->io, "ARTICLE %u",
				    data->cur);
				break;
			case NNTP_ARTICLE:
				if (code >= 100 && code <= 199)
					break;
				if (code == 423 || code == 430) {
					data->cur++;
					if (data->cur > data->last) {
						data->state = NNTP_QUIT;
						io_writeline(data->io, "QUIT");
						break;
					}
					data->state = NNTP_STAT;
					io_writeline(data->io, "STAT %u",
					    data->cur);
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
					data->state = NNTP_DONE;
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
			case NNTP_DONE:
				fatalx("unexpected state");
			case NNTP_QUIT:
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
	log_warnx("+++ STATE = %d", data->state);

	xfree(lbuf);
	io_flush(data->io, NULL);
	return (FETCH_ERROR);
}

int
nntp_delete(struct account *a)
{
	struct nntp_data	*data = a->data;
	char			*cause;

	cache_add(data->cache, data->key);
	if (cache_save(data->cache, &cause) != 0) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

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
