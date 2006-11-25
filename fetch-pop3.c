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

int	pop3_connect(struct account *);
int	pop3_disconnect(struct account *);
int	pop3_poll(struct account *, u_int *);
int	pop3_fetch(struct account *, struct mail *);
int	pop3_delete(struct account *);
int	pop3_keep(struct account *);
void	pop3_error(struct account *);
char   *pop3_desc(struct account *);
int	do_pop3(struct account *, u_int *, struct mail *, int);

struct fetch	fetch_pop3 = { { "pop3", "pop3s" },
			       pop3_connect,
			       pop3_poll,
			       pop3_fetch,
			       pop3_delete,
			       pop3_keep,
			       pop3_error,
			       pop3_disconnect,
			       pop3_desc
};

int
pop3_connect(struct account *a)
{
	struct pop3_data	*data = a->data;
	char			*cause;

	data->io = connectproxy(&data->server, conf.proxy, IO_CRLF, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = POP3_CONNECTING;

	return (0);
}

int
pop3_disconnect(struct account *a)
{
	struct pop3_data	*data = a->data;

	io_close(data->io);
	io_free(data->io);

	return (0);
}

void
pop3_error(struct account *a)
{
	struct pop3_data	*data = a->data;

	io_writeline(data->io, "QUIT");
	io_flush(data->io, NULL);
}

int
pop3_poll(struct account *a, u_int *n)
{
	return (do_pop3(a, n, NULL, 1));
}

int
pop3_fetch(struct account *a, struct mail *m)
{
	return (do_pop3(a, NULL, m, 0));
}

int
do_pop3(struct account *a, u_int *n, struct mail *m, int is_poll)
{
	struct pop3_data	*data = a->data;
	int		 	 res, flushing;
	char			*line, *cause, *ptr, *lbuf;
	size_t			 off = 0, size, len, llen;
	u_int			 lines = 0;

	if (m != NULL) {
		m->data = NULL;
		m->s = xstrdup(data->server.host);
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

			switch (data->state) {
			case POP3_CONNECTING:
				if (!pop3_isOK(line))
					goto error;

				data->state = POP3_USER;
				io_writeline(data->io, "USER %s", data->user);
				break;
			case POP3_USER:
				if (!pop3_isOK(line))
					goto error;

				data->state = POP3_PASS;
				io_writeline(data->io, "PASS %s", data->pass);
				break;
			case POP3_PASS:
				if (!pop3_isOK(line))
					goto error;

				data->state = POP3_STAT;
				io_writeline(data->io, "STAT");
				break;
			case POP3_STAT:
				if (!pop3_isOK(line))
					goto error;

				if (sscanf(line, "+OK %u %*u", &data->num) != 1)
					goto error;

				if (is_poll) {
					*n = data->num;
					data->state = POP3_QUIT;
					io_writeline(data->io, "QUIT");
					break;
				}

				if (data->num == 0) {
					data->state = POP3_QUIT;
					io_writeline(data->io, "QUIT");
					break;
				}

				data->cur = 1;
				data->state = POP3_LIST;
				io_writeline(data->io, "LIST %u", data->cur);
				break;
			case POP3_LIST:
				if (!pop3_isOK(line))
					goto error;

				if (sscanf(line, "+OK %*u %zu", &size) != 1)
					goto error;

				if (size == 0) {
					cause = xstrdup("zero-length message");
					goto error;
				}

				if (size > conf.max_size) {
					res = FETCH_OVERSIZE;
					data->state = POP3_DONE;
					break;
				}

				off = lines = 0;
				init_mail(m, IO_ROUND(size));

				data->state = POP3_RETR;
				io_writeline(data->io, "RETR %u", data->cur);
				break;
			case POP3_RETR:
				if (!pop3_isOK(line))
					goto error;

				data->state = POP3_LINE;
				break;
			case POP3_LINE:
				ptr = line;
				if (ptr[0] == '.' && ptr[1] != '\0')
					ptr++;
				else if (ptr[0] == '.') {
					if (off + lines != size) {
						log_warnx("%s: server lied "
						    "about message size: "
						    "expected %zu, got %zu "
						    "(%u lines)", a->name,
						    size, off + lines, lines);
					}
					m->size = off;

					if (flushing)
						res = FETCH_OVERSIZE;
					else
						res = FETCH_SUCCESS;
					data->state = POP3_DONE;
					break;
				}

				len = strlen(ptr);
				if (len == 0 && m->body == -1)
					m->body = off + 1;

				if (flushing) {
					lines++;
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
			case POP3_DONE:
				if (!pop3_isOK(line))
					goto error;

				data->cur++;
				if (data->cur > data->num) {
					data->state = POP3_QUIT;
					io_writeline(data->io, "QUIT");
					break;
				}

				data->state = POP3_LIST;
				io_writeline(data->io, "LIST %u", data->cur);
				break;
			case POP3_QUIT:
				if (!pop3_isOK(line))
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
pop3_delete(struct account *a)
{
	struct pop3_data	*data = a->data;

	data->state = POP3_DONE;

	io_writeline(data->io, "DELE %u", data->cur);

	return (0);
}

int
pop3_keep(struct account *a)
{
	struct pop3_data	*data = a->data;

	data->state = POP3_DONE;

	/* we don't need to /do/ anything here, but we need to poke the POP3
	   server so the response in the POP3_DONE state is a) there and
	   b) valid. this is not ideal, maybe it should be structured
	   differently */
	io_writeline(data->io, "NOOP");

	return (0);
}

char *
pop3_desc(struct account *a)
{
	struct pop3_data	*data = a->data;
	char			*s;

	xasprintf(&s, "pop3%s server \"%s\" port %s user \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user);
	return (s);
}
