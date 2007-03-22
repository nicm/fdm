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
#include "fetch.h"

int	fetch_pop3_start(struct account *, int *);
void	fetch_pop3_fill(struct account *, struct io **, u_int *);
int	fetch_pop3_finish(struct account *, int);
int	fetch_pop3_poll(struct account *, u_int *);
int	fetch_pop3_fetch(struct account *, struct mail *);
int	fetch_pop3_purge(struct account *);
int	fetch_pop3_done(struct account *, struct mail *);
void	fetch_pop3_desc(struct account *, char *, size_t);

void	fetch_pop3_free(void *);

int	fetch_pop3_connect(struct account *);
int	fetch_pop3_disconnect(struct account *, int);

int	fetch_pop3_line(struct account *, char **);
int	fetch_pop3_okay(char *);
char   *fetch_pop3_check(struct account *);

struct fetch fetch_pop3 = {
	"pop3",
	{ "pop3", "pop3s" },
	fetch_pop3_start,
	fetch_pop3_fill,
	fetch_pop3_poll,
	fetch_pop3_fetch,
	fetch_pop3_purge,
	fetch_pop3_done,
	fetch_pop3_finish,
	fetch_pop3_desc
};

void
fetch_pop3_free(void *ptr)
{
	struct fetch_pop3_mail	*aux = ptr;

	xfree(aux->uid);
	xfree(aux);
}

int
fetch_pop3_line(struct account *a, char **line)
{
	struct fetch_pop3_data	*data = a->data;
	struct io		*io = data->io;
	char			*cause;

	switch (io_pollline2(io, line, &data->lbuf, &data->llen, &cause)) {
	case 0:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (1);
	case -1:
		if (errno == EAGAIN)
			return (1);
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	return (0);
}

int
fetch_pop3_okay(char *line)
{
	if (strncmp(line, "+OK", 3) != 0)
		return (0);
	return (1);
}

char *
fetch_pop3_check(struct account *a)
{
	char			*line;

	if (fetch_pop3_line(a, &line) != 0)
		return (NULL);

	if (!fetch_pop3_okay(line)) {
		log_warnx("%s: unexpected data: %s", a->name, line);
		return (NULL);
	}

	return (line);
}

int
fetch_pop3_start(struct account *a, int *total)
{
	struct fetch_pop3_data	*data = a->data;
	int			 error;

	ARRAY_INIT(&data->kept);

	data->llen = IO_LINESIZE;
	data->lbuf = xmalloc(data->llen);

	data->state = POP3_START;

	if ((error = fetch_pop3_connect(a)) != FETCH_ERROR)
		*total = data->num;
	return (error);
}

void
fetch_pop3_fill(struct account *a, struct io **iop, u_int *n)
{
	struct fetch_pop3_data	*data = a->data;

	iop[(*n)++] = data->io;
}

int
fetch_pop3_finish(struct account *a, int aborted)
{
	struct fetch_pop3_data	*data = a->data;
	u_int			 i;

	if (data->io != NULL)
		fetch_pop3_disconnect(a, aborted);

	if (data->uid != NULL)
		xfree(data->uid);

	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++)
		xfree(ARRAY_ITEM(&data->kept, i, char *));
	ARRAY_FREE(&data->kept);

	xfree(data->lbuf);

	return (FETCH_SUCCESS);
}

int
fetch_pop3_connect(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line, *cause;

	data->io = connectproxy(&data->server,
	    conf.proxy, IO_CRLF, conf.timeout, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	if (fetch_pop3_check(a) == NULL)
		return (FETCH_ERROR);

	/* log the user in */
	io_writeline(data->io, "USER %s", data->user);
	if (fetch_pop3_check(a) == NULL)
		return (FETCH_ERROR);
	io_writeline(data->io, "PASS %s", data->pass);
	if (fetch_pop3_check(a) == NULL)
		return (FETCH_ERROR);

	/* find the number of messages */
	io_writeline(data->io, "STAT");
	if ((line = fetch_pop3_check(a)) == NULL)
		return (FETCH_ERROR);
	if (sscanf(line, "+OK %u %*u", &data->num) != 1) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (FETCH_ERROR);
	}

	data->cur = 0;

	return (FETCH_SUCCESS);
}

int
fetch_pop3_disconnect(struct account *a, int aborted)
{
	struct fetch_pop3_data	*data = a->data;

	io_writeline(data->io, "QUIT");
	if (!aborted && fetch_pop3_check(a) == NULL)
		goto error;

	io_close(data->io);
	io_free(data->io);

	return (FETCH_SUCCESS);

error:
	io_close(data->io);
	io_free(data->io);

	return (FETCH_ERROR);
}

int
fetch_pop3_poll(struct account *a, u_int *n)
{
	struct fetch_pop3_data	*data = a->data;

	*n = data->num;

	return (FETCH_SUCCESS);
}

int
fetch_pop3_fetch(struct account *a, struct mail *m)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	char			*line, *uid;
	size_t			 len;
	u_int			 n, i;

restart:
	line = NULL;
	if (data->state != POP3_START) {
		line = io_readline2(data->io, &data->lbuf, &data->llen);
		if (line == NULL)
			return (FETCH_AGAIN);
	}

	switch (data->state) {
	case POP3_START:
		data->cur++;
		if (data->cur > data->num)
			return (FETCH_COMPLETE);
		io_writeline(data->io, "LIST %u", data->cur);
		data->state = POP3_LIST;
		break;
	case POP3_LIST:
		if (!fetch_pop3_okay(line))
			goto bad;
		if (sscanf(line, "+OK %*u %zu", &data->size) != 1) {
			log_warnx("%s: invalid response: %s", a->name, line);
			return (FETCH_ERROR);
		}
		if (data->size == 0)
			return (FETCH_EMPTY);
		if (data->size > conf.max_size) {
			m->size = data->size;
			return (FETCH_OVERSIZE);
		}
		io_writeline(data->io, "UIDL %u", data->cur);
		data->state = POP3_UIDL;
		break;
	case POP3_UIDL:
		if (!fetch_pop3_okay(line))
			goto bad;
		if (sscanf(line, "+OK %u ", &n) != 1)
			goto bad;
		if (n != data->cur) {
			log_warnx("%s: unexpected message number: got %u, "
			    "expected %u", a->name, n, data->cur);
			return (FETCH_ERROR);
		}
		line = strchr(line, ' ');
		if (line == NULL)
			goto bad;
		line++;
		line = strchr(line, ' ');
		if (line == NULL)
			goto bad;
 		if (data->uid != NULL)
			xfree(data->uid);
		data->uid = xstrdup(line);
		for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
			uid = ARRAY_ITEM(&data->kept, i, char *);
			if (strcmp(data->uid, uid) == 0) {
				/*
				 * Seen this message before and kept it, so
				 * skip it this time.
				 */
				data->state = POP3_START;
				break;
			}
		}
		io_writeline(data->io, "RETR %u", data->cur);
		data->state = POP3_RETR;
		break;
	case POP3_RETR:
		if (!fetch_pop3_okay(line))
			goto bad;
		mail_open(m, IO_ROUND(data->size));
		m->size = 0;

		aux = xmalloc(sizeof *aux);
		aux->idx = data->cur;
		aux->uid = data->uid;
		data->uid = NULL;
		m->auxdata = aux;
		m->auxfree = fetch_pop3_free;

		default_tags(&m->tags, data->server.host, a);
		add_tag(&m->tags, "server", "%s", data->server.host);
		add_tag(&m->tags, "port", "%s", data->server.port);
		add_tag(&m->tags, "server_uid", "%s", data->uid);

		data->flushing = 0;
		data->lines = 0;
		data->bodylines = -1;

		data->state = POP3_LINE;
		break;
	case POP3_LINE:
		if (line[0] == '.' && line[1] == '.')
			line++;
		else if (line[0] == '.')
			goto complete;

		len = strlen(line);
		if (len == 0 && m->body == -1) {
			m->body = m->size + 1;
			data->bodylines = 0;
		}

		if (!data->flushing) {
			resize_mail(m, m->size + len + 1);

			if (len > 0)
				memcpy(m->data + m->size, line, len);
			m->data[m->size + len] = '\n';
		}

		data->lines++;
		if (data->bodylines != -1)
			data->bodylines++;
		m->size += len + 1;
		if (m->size + data->lines > conf.max_size)
			data->flushing = 1;
		break;
	}

	goto restart;

complete:
	data->state = POP3_START;

	add_tag(&m->tags, "lines", "%u", data->lines);
	if (data->bodylines == -1) {
		add_tag(&m->tags, "body_lines", "0");
		add_tag(&m->tags, "header_lines", "%u", data->lines - 1);
	} else {
		add_tag(&m->tags, "body_lines", "%d", data->bodylines - 1);
		add_tag(&m->tags, "header_lines", "%d", data->lines -
		    data->bodylines);
	}

	if (m->size + data->lines != data->size) {
		log_info("%s: server lied about message size: expected %zu, "
		    "got %zu (%u lines)", a->name, data->size, m->size +
		    data->lines, data->lines);
	}

	if (data->flushing)
		return (FETCH_OVERSIZE);

	return (FETCH_SUCCESS);

bad:
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (FETCH_ERROR);
}

int
fetch_pop3_purge(struct account *a)
{
	if (fetch_pop3_disconnect(a, 0) != 0)
		return (FETCH_ERROR);
	return (fetch_pop3_connect(a));
}

int
fetch_pop3_done(struct account *a, struct mail *m)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux = m->auxdata;

	if (m->decision == DECISION_KEEP) {
		ARRAY_ADD(&data->kept, xstrdup(aux->uid), char *);
		return (FETCH_SUCCESS);
	}

	io_writeline(data->io, "DELE %u", aux->idx);
	if (fetch_pop3_check(a) == NULL)
		return (FETCH_ERROR);
	return (FETCH_SUCCESS);
}

void
fetch_pop3_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_pop3_data	*data = a->data;

	xsnprintf(buf, len, "pop3%s server \"%s\" port %s user \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user);
}
