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

int	imap_connect(struct account *);
int	imap_disconnect(struct account *);
int	imap_tag(char *);
int	imap_okay(char *);
int	do_imap(struct account *, u_int *, struct mail *, int);

#define IMAP_TAG_NONE -1
#define IMAP_TAG_CONTINUE -2
#define IMAP_TAG_ERROR -3

struct fetch	fetch_imap = { "imap", "imap",
			       imap_connect, 
			       imap_poll,
			       imap_fetch,
			       imap_delete,
			       imap_error,
			       imap_disconnect };

int
imap_connect(struct account *a)
{
	struct imap_data	*data;
	char			*cause;

	data = a->data;

	if ((data->fd = connectto(&data->server, &cause)) < 0) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	data->io = io_create(data->fd, NULL, IO_CRLF);
	if (conf.debug > 3)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = IMAP_CONNECTING;
	data->tag = 0;

	return (0);
}

int
imap_disconnect(struct account *a)
{
	struct imap_data	*data;

	data = a->data;

	io_free(data->io);

	close(data->fd);

	return (0);
}

void
imap_error(struct account *a)
{
	struct imap_data	*data;

	data = a->data;

        io_writeline(data->io, "%u LOGOUT", ++data->tag);
        io_flush(data->io, NULL);
}

int
imap_poll(struct account *a, u_int *n)
{
	return (do_imap(a, n, NULL, 1));
}

int
imap_fetch(struct account *a, struct mail *m)
{
	return (do_imap(a, NULL, m, 0));
}

int
imap_tag(char *line) 
{
	long	tag;

	if (line[0] == '*' && line[1] == ' ')
		return (IMAP_TAG_NONE);
	if (line[0] == '+')
		return (IMAP_TAG_CONTINUE);
	
	errno = 0;
	tag = strtol(line, NULL, 10);
	if (tag == 0 && (errno == EINVAL || errno == ERANGE))
		return (IMAP_TAG_ERROR);

	return (tag);
}

int
imap_okay(char *line)
{
	line = strchr(line, ' ');
	if (line == NULL)
		return (0);
	return (strncmp(line + 1, "OK ", 3) == 0);
}

int
do_imap(struct account *a, u_int *n, struct mail *m, int is_poll)
{
	struct imap_data	*data;
	int		 	 v, res, flushing;
	long			 tag;
	char			*line, *cause, *lbuf, *folder;
	size_t			 off = 0, len, llen;
	u_int			 u, lines = 0;

	data = a->data;

	if (m != NULL)
		m->data = NULL;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	folder = data->folder;
	if (folder == NULL)
		folder = "INBOX";

	flushing = 0;
	line = cause = NULL;
	do {
		if (io_poll(data->io, &cause) != 1)
			goto error;

		res = -1;
		do {
			line = io_readline2(data->io, &lbuf, &llen);
			if (line == NULL)
				break;

			switch (data->state) {
			case IMAP_CONNECTING:
				if (imap_tag(line) != IMAP_TAG_NONE)
					goto error;

				data->state = IMAP_USER;
				io_writeline(data->io, 
				    "%u LOGIN {%zu}", ++data->tag, 
				    strlen(data->user));
				break;
			case IMAP_USER:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != IMAP_TAG_CONTINUE)
					goto error;

				data->state = IMAP_PASS;
				io_writeline(data->io, "%s {%zu}", data->user,
				    strlen(data->pass));
				break;
			case IMAP_PASS:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != IMAP_TAG_CONTINUE)
					goto error;

				data->state = IMAP_LOGIN;
				io_writeline(data->io, "%s", data->pass);
				break;
			case IMAP_LOGIN:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != data->tag)
					goto error;
				if (!imap_okay(line))
					goto error;

				data->state = IMAP_SELECT;
				if (is_poll)
					io_writeline(data->io, "%u EXAMINE %s",
					    ++data->tag, folder);
				else
					io_writeline(data->io, "%u SELECT %s",
					    ++data->tag, folder);
				break;
			case IMAP_SELECT:
				tag = imap_tag(line);
				if (tag != IMAP_TAG_NONE)
					goto error;

				v = sscanf(line, "* %u EXISTS", &data->num);
				if (v != 1)
					continue;
				data->state = IMAP_SELECTWAIT;
				break;
			case IMAP_SELECTWAIT:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != data->tag)
					goto error;
				if (!imap_okay(line))
					goto error;
				
				if (is_poll) {
					*n = data->num;
					data->state = IMAP_LOGOUT;
					io_writeline(data->io, "%u LOGOUT",
					    ++data->tag);
					break;
				}

				line = strchr(line, ' ' );
				if (line == NULL)
					goto error;
				line++;
				if (strncmp(line, "OK [READ-WRITE]", 15) != 0) {
					xasprintf(&cause, "can't open folder "
					    "read/write: %s", folder);
					goto error;
				}

				if (data->num == 0) {
					data->state = IMAP_CLOSE;
					io_writeline(data->io, "%u CLOSE",
					    ++data->tag);
					break;
				}

				data->cur = 1;
				data->state = IMAP_SIZE;
				io_writeline(data->io, "%u FETCH %u BODY[]",
				    ++data->tag, data->cur);
				break;
			case IMAP_SIZE:
				tag = imap_tag(line);
				if (tag != IMAP_TAG_NONE)
					goto error;

				if (sscanf(line, "* %u FETCH (BODY[] {%zu}",
				    &u, &m->size) != 2)
					goto error;
				if (u != data->cur) {
					cause = xstrdup("wrong message index");
					goto error;
				}

				if (m->size == 0) {
					cause = xstrdup("zero-length message");
					goto error;
				}

				if (m->size > conf.max_size)
					flushing = 1;

				off = lines = 0;
				m->base = m->data = xmalloc(m->size);
				m->space = m->size;
				m->body = -1;
				
				data->state = IMAP_LINE;
				break;
			case IMAP_LINE:
				len = strlen(line);
				if (len == 0 && m->body == -1)
					m->body = off + 1;
				
				if (!flushing) {
					resize_mail(m, off + len + 1);
					memcpy(m->data + off, line, len);
					/* append an LF */
					m->data[off + len] = '\n';
				}
				lines++;
				off += len + 1;

				if (off + lines >= m->size)
					data->state = IMAP_LINEWAIT;
				break;
			case IMAP_LINEWAIT:
				if (strcmp(line, ")") != 0)
					goto error;
				data->state = IMAP_LINEWAIT2;
				break;
			case IMAP_LINEWAIT2:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != data->tag)
					goto error;
				if (!imap_okay(line))
					goto error;

				if (off + lines != m->size) {
					cause = xstrdup("too much data");
					goto error;
				}
				m->size = off;

				if (flushing)
					res = FETCH_OVERSIZE;
				else
					res = FETCH_SUCCESS;
				
				data->state = IMAP_DONE;
				break;
			case IMAP_DONE:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != data->tag)
					goto error;
				if (!imap_okay(line))
					goto error;
					
				data->cur++;
				if (data->cur > data->num) {
					data->state = IMAP_CLOSE;
					io_writeline(data->io, "%u CLOSE",
					    ++data->tag);
					break;
				}

				data->state = IMAP_SIZE;
				io_writeline(data->io, "%u FETCH %u BODY[]",
				    ++data->tag, data->cur);
				break;
			case IMAP_CLOSE:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != data->tag)
					goto error;
				if (!imap_okay(line))
					goto error;

				data->state = IMAP_LOGOUT;
 				io_writeline(data->io, "%u LOGOUT",
				    ++data->tag);
				break;
			case IMAP_LOGOUT:
				tag = imap_tag(line);
				if (tag == IMAP_TAG_NONE)
					continue;
				if (tag != data->tag)
					goto error;
				if (!imap_okay(line))
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
imap_delete(struct account *a)
{
	struct imap_data	*data;

	data = a->data;

	io_writeline(data->io, "%u STORE %u +FLAGS \\Deleted", ++data->tag,
	    data->cur);

	return (0);
}
