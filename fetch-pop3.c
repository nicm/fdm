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

int	fetch_pop3_connect(struct account *);
void	fetch_pop3_fill(struct account *, struct io **, u_int *);
u_int	fetch_pop3_total(struct account *);
int	fetch_pop3_completed(struct account *);
int	fetch_pop3_closed(struct account *);
int	fetch_pop3_fetch(struct account *, struct fetch_ctx *);
int	fetch_pop3_poll(struct account *, u_int *);
int	fetch_pop3_purge(struct account *);
int	fetch_pop3_close(struct account *);
int	fetch_pop3_disconnect(struct account *, int);
void	fetch_pop3_desc(struct account *, char *, size_t);

int	fetch_pop3_reconnect(struct account *);

void	fetch_pop3_free(void *);
int	fetch_pop3_okay(const char *);

int	fetch_pop3_bad(struct account *, const char *);
int	fetch_pop3_invalid(struct account *, const char *);

int	fetch_pop3_connected(struct account *, struct fetch_ctx *);
int	fetch_pop3_user(struct account *, struct fetch_ctx *);
int	fetch_pop3_stat(struct account *, struct fetch_ctx *);
int	fetch_pop3_first(struct account *, struct fetch_ctx *);
int	fetch_pop3_next(struct account *, struct fetch_ctx *);
int	fetch_pop3_purged(struct account *, struct fetch_ctx *);
int	fetch_pop3_delete(struct account *, struct fetch_ctx *);
int	fetch_pop3_list(struct account *, struct fetch_ctx *);
int	fetch_pop3_uidl(struct account *, struct fetch_ctx *);
int	fetch_pop3_retr(struct account *, struct fetch_ctx *);
int	fetch_pop3_line(struct account *, struct fetch_ctx *);
int	fetch_pop3_quit(struct account *, struct fetch_ctx *);

struct fetch fetch_pop3 = {
	"pop3",
	fetch_pop3_connect,
	fetch_pop3_fill,
	fetch_pop3_total,
	fetch_pop3_completed,
	fetch_pop3_closed,
	fetch_pop3_fetch,
	fetch_pop3_poll,
	fetch_pop3_purge,
	fetch_pop3_close,
	fetch_pop3_disconnect,
	fetch_pop3_desc
};

void
fetch_pop3_free(void *ptr)
{
	struct fetch_pop3_mail	*aux = ptr;

	if (aux->uid != NULL)
		xfree(aux->uid);
	xfree(aux);
}

int
fetch_pop3_okay(const char *line)
{
	return (strncmp(line, "+OK", 3) == 0);
}

/* Connect to POP3 server. */
int
fetch_pop3_connect(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

 	ARRAY_INIT(&data->kept);

	data->llen = IO_LINESIZE;
	data->lbuf = xmalloc(data->llen);

	return (fetch_pop3_reconnect(a));
}

/* Reconnect to POP3 server. */
int
fetch_pop3_reconnect(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;
	char			*cause;

	data->io = connectproxy(&data->server,
	    conf.verify_certs, conf.proxy, IO_CRLF, conf.timeout, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = fetch_pop3_connected;
	return (0);
}

/* Fill io array. */
void
fetch_pop3_fill(struct account *a, struct io **iop, u_int *n)
{
	struct fetch_pop3_data	*data = a->data;

	iop[(*n)++] = data->io;
}

/* Return total mails available. */
u_int
fetch_pop3_total(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	return (data->total);
}

/* Return if fetch is complete. */
int
fetch_pop3_completed(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	return (data->cur > data->num);
}

/* Return if fetch is closed. */
int
fetch_pop3_closed(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	return (data->close && data->io == NULL);
}

/* Clean up and disconnect from server. */
int
fetch_pop3_disconnect(struct account *a, unused int aborted)
{
	struct fetch_pop3_data	*data = a->data;
	u_int			 i;

	if (data->mail != NULL)
		mail_destroy(data->mail);

	if (data->io != NULL) {
		io_close(data->io);
		io_free(data->io);
	}

	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++)
		xfree(ARRAY_ITEM(&data->kept, i));
	ARRAY_FREE(&data->kept);

	xfree(data->lbuf);

	return (0);
}

/* Fetch mail. */
int
fetch_pop3_fetch(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;

	return (data->state(a, fctx));
}

/* Poll for mail. */
int
fetch_pop3_poll(struct account *a, u_int *total)
{
	struct fetch_pop3_data	*data = a->data;
	struct io		*rio;
	char			*cause;
	int		 	 timeout;

	for (;;) {
		timeout = 0;
		switch (fetch_pop3_fetch(a, NULL)) {
		case FETCH_ERROR:
			return (-1);
		case FETCH_BLOCK:
			timeout = conf.timeout;
			break;
		case FETCH_HOLD:
			continue;
		}

		if (data->io == NULL)
			break;
		if (data->state == fetch_pop3_next) {
			io_writeline(data->io, "QUIT");
			data->state = fetch_pop3_quit;
		}

		switch (io_polln(&data->io, 1, &rio, timeout, &cause)) {
		case 0:
			log_warnx("%s: connection closed", a->name);
			return (-1);
		case -1:
			if (errno == EAGAIN)
				break;
			log_warnx("%s: %s", a->name, cause);
			xfree(cause);
			return (-1);
		}
	}

	*total = data->total;
	return (0);
}

/* Purge deleted mail. */
int
fetch_pop3_purge(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	data->purge = 1;

	return (0);
}

/* Close down connection. */
int
fetch_pop3_close(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	data->close = 1;

	return (0);
}

int
fetch_pop3_bad(struct account *a, const char *line)
{
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (FETCH_ERROR);
}

int
fetch_pop3_invalid(struct account *a, const char *line)
{
	log_warnx("%s: invalid response: %s", a->name, line);
	return (FETCH_ERROR);
}

/* Connected state: wait for initial +OK line from server. */
int
fetch_pop3_connected(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	io_writeline(data->io, "USER %s", data->user);
	data->state = fetch_pop3_user;
	return (FETCH_BLOCK);
}

/* USER state. */
int
fetch_pop3_user(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	io_writeline(data->io, "PASS %s", data->pass);
	data->state = fetch_pop3_stat;
	return (FETCH_BLOCK);
}

/* STAT state. */
int
fetch_pop3_stat(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	io_writeline(data->io, "STAT");
	data->state = fetch_pop3_first;
	return (FETCH_BLOCK);
}

/* First state. Wait for +OK then switch to get first mail. */
int
fetch_pop3_first(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	if (sscanf(line, "+OK %u %*u", &data->num) != 1)
		return (fetch_pop3_invalid(a, line));
	data->cur = 0;

	/* Save total in case we purge and get a new data->num. */
	if (data->total == 0)
		data->total = data->num;

	data->state = fetch_pop3_next;
	return (FETCH_AGAIN);
}

/*
 * Next state. This is the transition state between mails so deleting/purging
 * is done here if possible. This is also where the fetch code idles when
 * no more mails are available, waiting for them to be moved on to the done
 * queue. This must be moved to via FETCH_AGAIN to avoid blocking waiting for
 * a line from the server that will never come.
 */
int
fetch_pop3_next(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	struct mail		*m;

	/* Delete mail if any to be deleted. */
	while ((m = done_mail(a, fctx)) != NULL) {
		aux = m->auxdata;
		if (m->decision == DECISION_KEEP) {
			ARRAY_ADD(&data->kept, xstrdup(aux->uid));
			dequeue_mail(a, fctx);
		} else {
			io_writeline(data->io, "DELE %u", aux->idx);
			data->state = fetch_pop3_delete;
			return (FETCH_BLOCK);
		}
	}

	/* Need to purge and reconnect. */
	if (data->purge) {
		/*
		 * Keep looping through this state until the caller reckons
		 * we are ready to purge.
		 */
		if (!can_purge(a, fctx))
			return (FETCH_HOLD);

		io_writeline(data->io, "QUIT");
		data->state = fetch_pop3_purged;
		return (FETCH_BLOCK);
	}

	/* Close down connection nicely if asked. */
	if (data->close) {
		io_writeline(data->io, "QUIT");
		data->state = fetch_pop3_quit;
		return (FETCH_BLOCK);
	}

	/* Move to the next mail if possible. */
	if (!fetch_pop3_completed(a))
		data->cur++;
	if (fetch_pop3_completed(a))
		return (FETCH_HOLD);

	/*
	 * Create a new mail, unless one was left by previously kept mail that
	 * can be reused.
	 */
	if (data->mail == NULL) {
		m = data->mail = xcalloc(1, sizeof *data->mail);
		m->shm.fd = -1;
	}

	/* List the next mail. */
	io_writeline(data->io, "LIST %u", data->cur);
	data->state = fetch_pop3_list;
	return (FETCH_BLOCK);
}

/* Purge state. */
int
fetch_pop3_purged(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	data->purge = 0;

	io_close(data->io);
	io_free(data->io);
	if (fetch_pop3_reconnect(a) != 0)
		return (FETCH_ERROR);

	data->state = fetch_pop3_connected;
	return (FETCH_BLOCK);
}

/* Delete state. Wait for +OK then dequeue the mail. */
int
fetch_pop3_delete(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	dequeue_mail(a, fctx);

	data->state = fetch_pop3_next;
	return (FETCH_AGAIN);
}

/* LIST state. */
int
fetch_pop3_list(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = data->mail;
	struct fetch_pop3_mail	*aux;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	if (sscanf(line, "+OK %*u %zu", &data->size) != 1)
		return (fetch_pop3_invalid(a, line));
	m->size = data->size;

	/* Fill in local data. */
	aux = xcalloc(1, sizeof *aux);
	aux->idx = data->cur;
	m->auxdata = aux;
	m->auxfree = fetch_pop3_free;

	/* Deal with empty and oversize mails. */
	if (data->size == 0) {
		if (empty_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		data->mail = NULL;
		data->state = fetch_pop3_next;
		return (FETCH_AGAIN);
	}
	if (data->size > conf.max_size) {
		if (oversize_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		data->mail = NULL;
		data->state = fetch_pop3_next;
		return (FETCH_AGAIN);
	}

	io_writeline(data->io, "UIDL %u", data->cur);
	data->state = fetch_pop3_uidl;
	return (FETCH_BLOCK);
}

/* UIDL state. Get and save the UID. */
int
fetch_pop3_uidl(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = data->mail;
 	struct fetch_pop3_mail	*aux = m->auxdata;
	char			*line;
	u_int			 n, i;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	if (sscanf(line, "+OK %u ", &n) != 1)
		return (fetch_pop3_bad(a, line));
	if (n != data->cur)
		return (fetch_pop3_bad(a, line));
	
	line = strchr(line, ' ');
	if (line == NULL)
		return (fetch_pop3_bad(a, line));
	line = strchr(line + 1, ' ');
	if (line == NULL)
		return (fetch_pop3_bad(a, line));

	aux->uid = xstrdup(line);
	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
		if (strcmp(aux->uid, ARRAY_ITEM(&data->kept, i)) == 0) {
			/*
			 * Seen this message before and kept it, so skip it
			 * this time.
			 */
			data->state = fetch_pop3_next;
			return (FETCH_AGAIN);
		}
	}

	io_writeline(data->io, "RETR %u", data->cur);
	data->state = fetch_pop3_retr;
	return (FETCH_BLOCK);
}

/* RETR state. */
int
fetch_pop3_retr(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = data->mail;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	/* Open the mail. */
	if (mail_open(m, IO_ROUND(data->size)) != 0) {
		log_warn("%s: failed to create mail", a->name);
		return (FETCH_ERROR);
	}
	m->size = 0;

	data->flushing = 0;
	data->lines = 0;
	data->bodylines = -1;

	data->state = fetch_pop3_line;
	return (FETCH_BLOCK);
}

/* Line state. */
int
fetch_pop3_line(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = data->mail;
	struct fetch_pop3_mail	*aux = m->auxdata;
	char			*line;
	size_t			 len;

	for (;;) {
		line = io_readline2(data->io, &data->lbuf, &data->llen);
		if (line == NULL)
			return (FETCH_BLOCK);

		if (line[0] == '.' && line[1] == '.')
			line++;
		else if (line[0] == '.')
			break;

		len = strlen(line);
		if (len == 0 && m->body == -1) {
			m->body = m->size + 1;
			data->bodylines = 0;
		}

		if (!data->flushing) {
			if (mail_resize(m, m->size + len + 1) != 0) {
				log_warn("%s: failed to resize mail", a->name);
				return (FETCH_ERROR);
			}

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
	}

	/* Tag mail. */
	default_tags(&m->tags, data->server.host, a);
	add_tag(&m->tags, "server", "%s", data->server.host);
	add_tag(&m->tags, "port", "%s", data->server.port);
	add_tag(&m->tags, "server_uid", "%s", aux->uid);

	add_tag(&m->tags, "lines", "%u", data->lines);
	if (data->bodylines == -1) {
		add_tag(&m->tags, "body_lines", "0");
		add_tag(&m->tags, "header_lines", "%u", data->lines - 1);
	} else {
		add_tag(&m->tags, "body_lines", "%d", data->bodylines - 1);
		add_tag(&m->tags,
		    "header_lines", "%d", data->lines - data->bodylines);
	}

	/* Accept size with either CRLF or just LF line endings. */
	if (!data->flushing &&
	    m->size + data->lines != data->size && m->size != data->size) {
		log_warnx("%s: server lied about message size: expected %zu, "
		    "got %zu (%u lines)", a->name, data->size, m->size +
		    data->lines, data->lines);
	}

	if (data->flushing) {
		if (oversize_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		data->mail = NULL;
		data->state = fetch_pop3_next;
		return (FETCH_AGAIN);
	}
	transform_mail(a, fctx, m);
	if (m->size == 0) {
		if (empty_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		data->mail = NULL;
		data->state = fetch_pop3_next;
		return (FETCH_AGAIN);
	}
	enqueue_mail(a, fctx, m);
	data->mail = NULL;

	data->state = fetch_pop3_next;
	return (FETCH_AGAIN);
}

/* QUIT state. */
int
fetch_pop3_quit(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	io_close(data->io);
	io_free(data->io);
	data->io = NULL;

	data->state = fetch_pop3_next;
	return (FETCH_AGAIN);
}

void
fetch_pop3_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_pop3_data	*data = a->data;

	xsnprintf(buf, len, "pop3%s server \"%s\" port %s user \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user);
}
