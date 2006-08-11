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
int	do_pop3(struct account *, u_int *, struct mail *, int);

struct fetch	fetch_pop3 = { "pop3", "pop3",
			       pop3_connect, 
			       pop3_poll,
			       pop3_fetch, 
			       pop3_disconnect };

int
pop3_connect(struct account *a)
{
	struct pop3_data	*data;
	char			*cause;

	data = a->data;

	if ((data->fd = connectto(data->ai, &cause)) < 0) {
		log_warn("%s: %s", a->name, cause);
		return (1);
	}

	data->io = io_create(data->fd, NULL, IO_CRLF);
	if (conf.debug > 2)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = POP3_CONNECTING;

	return (0);
}

int
pop3_disconnect(struct account *a)
{
	struct pop3_data	*data;

	data = a->data;

	io_free(data->io);

	close(data->fd);

	return (0);
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
	struct pop3_data	*data;
	int		 	 done;
	char			*line = NULL, *ptr;
	size_t			 off = 0, len;

	data = a->data;
	if (m != NULL)
		m->data = NULL;

	/* We want to be paranoid and not delete the message until it has been
	   dealt with by the caller and the next one asked for but equally we
	   don't want to complicate the state machine by having one event which
	   isn't triggered by a line being ready, so this is special-cased
	   here */
	if (data->state == POP3_DELE) {
		data->state = POP3_DONE;
		io_writeline(data->io, "DELE %u", data->cur);
	}

	for (;;) {
		if (io_poll(data->io) != 1)
			goto error2;

		done = 0;
		while (!done) {
			line = io_readline(data->io);
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

				if (sscanf(line, "+OK %*u %zu", &m->size) != 1)
					goto error;

				if (m->size == 0) {
					log_warnx("%s: bad message size: %zu", 
					    m->size);
					goto error2;
				}

				if (m->size > conf.max_size) {
					log_warnx("%s: message too big: %zu",
					    m->size);
					goto error2;
				}
				
				off = 0;
				m->data = xmalloc(m->size);
				m->space = m->size;
				m->body = -1;
				
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
					if (off != m->size) {
						log_warnx("%s: server lied "
						    "about message size: "
						    "expected %zu, got %zu", 
						    a->name, m->size, off);
					}
					m->size = off;

					done = 1;
					data->state = POP3_DELE;
					break;
				}
				len = strlen(ptr);
				if (len == 0 && m->body == -1)
					m->body = off + 2;

				ENSURE_SIZE(m->data, m->space, off + len + 1);

				if (len > 0)
					memcpy(m->data + off, ptr, len);
				/* append an LF */
				m->data[off + len] = '\n';
				off += len + 1;
				break;
			case POP3_DELE:	
				fatalx("invalid state reached");
			case POP3_DONE:
				if (!pop3_isOK(line))
					goto error;
				
				data->cur++;
				if (data->cur > data->num) {
					data->state = POP3_QUIT;
					io_writeline(data->io, "QUIT");
					break;
				}
				
				io_writeline(data->io, "LIST %u", data->cur);
				data->state = POP3_LIST;
				break;
			case POP3_QUIT:
				if (!pop3_isOK(line))
					goto error;

				done = 1;
				break;
			}

			xfree(line);
		}
		if (done)
			break;
	}

	io_flush(data->io);
	return (0);

error:
	log_warnx("%s: %s", a->name, line);

error2:
	if (line != NULL)
		xfree(line);

	io_writeline(data->io, "QUIT");
	io_flush(data->io);
	return (1);
}
