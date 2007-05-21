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

#include <string.h>

#include "fdm.h"
#include "fetch.h"

int	imap_putln(struct account *, const char *, ...);
int	imap_getln(struct account *, int, char **);

void	imap_free(void *);
int	imap_okay(struct account *, char *);
int	imap_parse(struct account *, int, char *);
int	imap_tag(char *);

int	fetch_imap_bad(struct account *, const char *);
int	fetch_imap_invalid(struct account *, const char *);

int	imap_connected(struct account *, struct fetch_ctx *);
int	imap_login(struct account *, struct fetch_ctx *);
int	imap_user(struct account *, struct fetch_ctx *);
int	imap_pass(struct account *, struct fetch_ctx *);
int	imap_select1(struct account *, struct fetch_ctx *);
int	imap_select2(struct account *, struct fetch_ctx *);
int	imap_select3(struct account *, struct fetch_ctx *);
int	imap_next(struct account *, struct fetch_ctx *);
int	imap_uid1(struct account *, struct fetch_ctx *);
int	imap_uid2(struct account *, struct fetch_ctx *);
int	imap_body(struct account *, struct fetch_ctx *);
int	imap_line(struct account *, struct fetch_ctx *);
int	imap_delete(struct account *, struct fetch_ctx *);
int	imap_expunge(struct account *, struct fetch_ctx *);
int	imap_quit1(struct account *, struct fetch_ctx *);
int	imap_quit2(struct account *, struct fetch_ctx *);

/* Put line to server. */
int
imap_putln(struct account *a, const char *fmt, ...)
{
	struct fetch_imap_data	*data = a->data;
	va_list			 ap;
	int			 n;

	va_start(ap, fmt);
	n = data->putln(a, fmt, ap);
	va_end(ap);

	return (n);
}

/* Get line from server. */
int
imap_getln(struct account *a, int type, char **line)
{
	struct fetch_imap_data	*data = a->data;
 	int			 n;

	if ((n = data->getln(a, line)) != 0)
		return (n);
	return (imap_parse(a, type, *line));
}

/* Free auxiliary data. */
void
imap_free(void *ptr)
{
	xfree(ptr);
}

/* Check for okay from server. */
int
imap_okay(struct account *a, char *line)
{
	char	*ptr;

	ptr = strchr(line, ' ');
	if (ptr == NULL || strncmp(ptr + 1, "OK ", 3) != 0) {
		log_warnx("%s: unexpected data: %s", a->name, line);
		return (0);
	}

	return (1);
}

/* Parse line based on type. */
int
imap_parse(struct account *a, int type, char *line)
{
	struct fetch_imap_data	*data = a->data;
	int			 tag;

	if (type == IMAP_RAW)
		return (0);
	tag = imap_tag(line);
	switch (type) {
	case IMAP_TAGGED:
		if (tag == IMAP_TAG_NONE)
			return (1);
		if (tag == IMAP_TAG_CONTINUE)
			goto invalid;
		if (tag != data->tag)
			goto invalid;
		break;
	case IMAP_UNTAGGED:
		if (tag != IMAP_TAG_NONE)
			goto invalid;
		break;
	case IMAP_CONTINUE:
		if (tag == IMAP_TAG_NONE)
			return (1);
		if (tag != IMAP_TAG_CONTINUE)
			goto invalid;
		break;
	}

	return (0);

invalid:
	fetch_imap_bad(a, line);
	return (-1);
}

/* Parse IMAP tag  */
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

/* Set up on connect. */
int
imap_connect(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	fatalx("XXX IMAP is currently broken");

	ARRAY_INIT(&data->kept);

	data->llen = IO_LINESIZE;
	data->lbuf = xmalloc(data->llen);

	data->tag = 0;

	data->state = imap_connected;
	return (0);
}

/* Return total mails available. */
u_int
imap_total(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	return (data->total);
}

/* Return if fetch is complete. */
int
imap_completed(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	return (data->cur > data->num);
}

/* Return if fetch is closed. */
int
imap_closed(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	return (data->close && data->io == NULL);
}

/* Clean up on disconnect. */
int
imap_disconnect(struct account *a, unused int aborted)
{
	struct fetch_imap_data	*data = a->data;

	ARRAY_FREE(&data->kept);

	xfree(data->lbuf);

	return (0);
}

/* Fetch mail. */
int
imap_fetch(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	return (data->state(a, fctx));
}

/* Purge deleted mail. */
int
imap_purge(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	data->purge = 1;

	return (0);
}

/* Close down connection. */
int
imap_close(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	data->close = 1;

	return (0);
}

int
fetch_imap_bad(struct account *a, const char *line)
{
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (FETCH_ERROR);
}

int
fetch_imap_invalid(struct account *a, const char *line)
{
	log_warnx("%s: invalid response: %s", a->name, line);
	return (FETCH_ERROR);
}

/* Connected state: wait for initial line from server. */
int
imap_connected(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_UNTAGGED, line) != 0)
		return (FETCH_ERROR);

	if (strncmp(line, "* PREAUTH", 9) == 0) {
		data->state = imap_select1;
		return (FETCH_AGAIN);
	}
	if (data->user == NULL || data->pass == NULL) {
		log_warnx("%s: not PREAUTH and no user or password", a->name);
		return (FETCH_ERROR);
	}

	if (imap_putln(a,
	    "%u LOGIN {%zu}", ++data->tag, strlen(data->user)) != 0)
		return (FETCH_ERROR);
	data->state = imap_login;
	return (FETCH_BLOCK);
}

/* Login state. */
int
imap_login(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_CONTINUE, line) != 0)
		return (FETCH_ERROR);

	if (imap_putln(a, "%s {%zu}", data->user, strlen(data->pass)) != 0)
		return (FETCH_ERROR);
	data->state = imap_user;
	return (FETCH_BLOCK);
}

/* User state. */
int
imap_user(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_CONTINUE, line) != 0)
		return (FETCH_ERROR);

	if (imap_putln(a, "%s", data->pass) != 0)
		return (FETCH_ERROR);
	data->state = imap_pass;
	return (FETCH_BLOCK);
}

/* Pass state. */
int
imap_pass(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_TAGGED, line) != 0)
		return (FETCH_ERROR);

	if (!imap_okay(a, line))
		return (fetch_imap_bad(a, line));

	data->state = imap_select1;
	return (FETCH_AGAIN);
}

/* Select state 1. */
int
imap_select1(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	if (imap_putln(a, "%u SELECT %s", ++data->tag, data->folder) != 0)
		return (FETCH_ERROR);
	data->state = imap_select2;
	return (FETCH_BLOCK);
}

/* Select state 2. Hold until select returns message count. */
int
imap_select2(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_UNTAGGED, line) != 0)
		return (FETCH_ERROR);

	if (sscanf(line, "* %u EXISTS", &data->num) != 1)
		return (FETCH_BLOCK);
	data->cur = 0;

	if (data->total == 0)
		data->total = data->num;

	data->state = imap_select3;
	return (FETCH_BLOCK);
}

/* Select state 3. Hold until select completes then get next mail. */
int
imap_select3(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_TAGGED, line) != 0)
		return (FETCH_ERROR);

	if (!imap_okay(a, line))
		return (fetch_imap_bad(a, line));

	data->state = imap_next;
	return (FETCH_AGAIN);
}

/* 
 * Next state. Get next mail. This is also the idle state when completed, so
 * check for finished mail, exiting, and so on.
 */
int
imap_next(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	struct fetch_imap_mail	*aux;
	struct mail		*m;

	/* Delete mail if any to be deleted. */
	while ((m = done_mail(a, fctx)) != NULL) {
		aux = m->auxdata;
		if (m->decision == DECISION_KEEP) {
			ARRAY_ADD(&data->kept, aux->uid);
			dequeue_mail(a, fctx);
		} else {
			if (imap_putln(a, "%u STORE %u +FLAGS \\Deleted", 
			    ++data->tag, aux->idx) != 0)
				return (FETCH_ERROR);
			data->state = imap_delete;
			return (FETCH_BLOCK);
		}
	}

	/* Need to purge. */
	if (data->purge) {
		/*
		 * Keep looping through this state until the caller reckons
		 * we are ready to purge.
		 */
		if (!can_purge(a, fctx))
			return (FETCH_HOLD);

		if (imap_putln(a, "%u EXPUNGE", ++data->tag) != 0)
			return (FETCH_ERROR);
		data->state = imap_expunge;
		return (FETCH_BLOCK);
	}

	/* Close down connection nicely if asked. */
	if (data->close) {
		if (imap_putln(a, "%u CLOSE", ++data->tag) != 0)
			return (FETCH_ERROR);
		data->state = imap_quit1;
		return (FETCH_BLOCK);
	}

	/* Move to the next mail if possible. */
	if (!imap_completed(a))
		data->cur++;
	if (imap_completed(a))
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
	if (imap_putln(a, "%u FETCH %u UID", ++data->tag, data->cur) != 0)
		return (FETCH_ERROR);
	data->state = imap_uid1;
	return (FETCH_BLOCK);
}

/* UID state 1. */
int
imap_uid1(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;
	u_int			 n;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_UNTAGGED, line) != 0)
		return (FETCH_ERROR);

	if (sscanf(line, "* %u FETCH (UID %u)", &n, &data->uid) != 2)
		return (fetch_imap_invalid(a, line));
	if (n != data->cur) {
		log_warnx("%s: bad message index: %s", a->name, line);
		return (FETCH_ERROR);
	}
	
	data->state = imap_uid2;
	return (FETCH_BLOCK);
}

/* UID state 2. */
int
imap_uid2(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;
	u_int			 i;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_TAGGED, line) != 0)
		return (FETCH_ERROR);

	if (!imap_okay(a, line))
		return (fetch_imap_bad(a, line));
	
	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
		if (ARRAY_ITEM(&data->kept, i) == data->uid) {
			/* Had this message before and kept, so skip. */
			data->state = imap_next;
			break;
		}
	}

	if (imap_putln(a, "%u FETCH %u BODY[]", ++data->tag, data->cur) != 0)
		return (FETCH_ERROR);
	data->state = imap_body;
	return (FETCH_BLOCK);
}

/* Body state. */
int
imap_body(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	struct mail		*m = data->mail;
	struct fetch_imap_mail	*aux;
	char			*line, *ptr;
	u_int			 n;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_UNTAGGED, line) != 0)
		return (FETCH_ERROR);

	if (sscanf(line, "* %u FETCH (", &n) != 1)
		return (fetch_imap_invalid(a, line));
	if ((ptr = strstr(line, "BODY[] {")) == NULL)	
		return (fetch_imap_invalid(a, line));

	if (sscanf(ptr, "BODY[] {%zu}", &data->size) != 1)
		return (fetch_imap_invalid(a, line));
	if (n != data->cur) {
		log_warnx("%s: bad message index: %s", a->name, line);
		return (FETCH_ERROR);
	}
	m->size = data->size;

	/* Fill in local data. */
	aux = xcalloc(1, sizeof *aux);
	aux->idx = data->cur;
	aux->uid = data->uid;
	m->auxdata = aux;
	m->auxfree = imap_free;
	
	/* Deal with empty and oversize mails. */
	if (data->size == 0) {
		if (empty_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		data->mail = NULL;
		data->state = imap_next;
		return (FETCH_AGAIN);
	}
	if (data->size > conf.max_size) {
		if (oversize_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		data->mail = NULL;
		data->state = imap_next;
		return (FETCH_AGAIN);
	}

	/* Open the mail. */
	if (mail_open(m, IO_ROUND(data->size)) != 0) {
		log_warn("%s: failed to create mail", a->name);
		return (FETCH_ERROR);
	}
	m->size = 0;

	/* Fill in tags. */
	default_tags(&m->tags, data->server.host, a);
	if (data->server.host != NULL) {
		add_tag(&m->tags, "server", "%s", data->server.host);
		add_tag(&m->tags, "port", "%s", data->server.port);
	}
	add_tag(&m->tags, "server_uid", "%u", data->uid);
	add_tag(&m->tags, "folder", "%s", data->folder);

	data->flushing = data->size > conf.max_size;
	data->lines = 0;
	data->bodylines = -1;
	
	data->state = imap_line;
	return (FETCH_BLOCK);
}

/* Line state. */ 
int
imap_line(struct account *a, unused struct fetch_ctx *fctx)
{
	/*XXX*/
}

/* Delete state. */ 
int
imap_delete(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_TAGGED, line) != 0)
		return (FETCH_ERROR);

	if (!imap_okay(a, line))
		return (fetch_imap_bad(a, line));

	data->state = imap_next;
	return (FETCH_AGAIN);
}

/* Expunge state. */ 
int
imap_expunge(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_TAGGED, line) != 0)
		return (FETCH_ERROR);

	if (!imap_okay(a, line))
		return (fetch_imap_bad(a, line));

	data->state = imap_select1;
	return (FETCH_AGAIN);
}

/* Quit state 1. */
int
imap_quit1(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_TAGGED, line) != 0)
		return (FETCH_ERROR);

	if (!imap_okay(a, line))
		return (fetch_imap_bad(a, line));

	if (imap_putln(a, "%u LOGOUT", ++data->tag) != 0)
		return (1);
	data->state = imap_quit2;
	return (FETCH_BLOCK);
}

/* Quit state 2. */
int
imap_quit2(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &data->lbuf, &data->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (imap_parse(a, IMAP_TAGGED, line) != 0)
		return (FETCH_ERROR);

	if (!imap_okay(a, line))
		return (fetch_imap_bad(a, line));

	io_close(data->io);
	io_free(data->io);
	data->io = NULL;

	data->state = imap_next;
	return (FETCH_AGAIN);
}

#if 0
int
imap_fetch(struct account *a, struct mail *m)
{
	struct fetch_imap_data	*data = a->data;
	struct fetch_imap_mail	*aux = m->auxdata;
	char			*line, *ptr;
	u_int	 		 n, i;
	int			 type;
	size_t			 len;

restart:
	type = -1;
	switch (data->state) {
	case IMAP_UID1:
	case IMAP_FETCH:
		type = IMAP_UNTAGGED;
		break;
	case IMAP_UID2:
	case IMAP_END2:
		type = IMAP_TAGGED;
		break;
	case IMAP_LINE:
	case IMAP_END1:
		type = IMAP_RAW;
		break;
	default:
		break;
	}
	if (type != -1) {
		switch (imap_getln(a, type, &line)) {
		case -1:
			return (FETCH_ERROR);
		case 1:
			return (FETCH_AGAIN);
		}
	}

	switch (data->state) {
	case IMAP_START:
		data->cur++;
		if (data->cur > data->num)
			return (FETCH_COMPLETE);

		if (imap_putln(a,
		    "%u FETCH %u UID", ++data->tag, data->cur) != 0)
			return (FETCH_ERROR);
		data->state = IMAP_UID1;
		break;
	case IMAP_UID1:
		if (sscanf(line, "* %u FETCH (UID %u)", &n, &data->uid) != 2) {
			log_warnx("%s: invalid response: %s", a->name, line);
			return (FETCH_ERROR);
		}
		if (n != data->cur) {
			log_warnx("%s: bad message index: %s", a->name, line);
			return (FETCH_ERROR);
		}
		data->state = IMAP_UID2;
		break;
	case IMAP_UID2:
		if (!imap_okay(a, line))
			return (FETCH_ERROR);

		for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
			if (ARRAY_ITEM(&data->kept, i) == data->uid) {
				/* had this message before and kept, so skip */
				data->state = IMAP_START;
				break;
			}
		}
 		if (imap_putln(a,
		    "%u FETCH %u BODY[]", ++data->tag, data->cur) != 0)
			return (FETCH_ERROR);
		data->state = IMAP_FETCH;
		break;
	case IMAP_FETCH:
		if (sscanf(line, "* %u FETCH (", &n) != 1) {
			log_warnx("%s: invalid response: %s", a->name, line);
			return (FETCH_ERROR);
		}
		if ((ptr = strstr(line, "BODY[] {")) == NULL) {
			log_warnx("%s: invalid response: %s", a->name, line);
			return (FETCH_ERROR);
		}

		if (sscanf(ptr, "BODY[] {%zu}", &data->size) != 1) {
			log_warnx("%s: invalid response: %s", a->name, line);
			return (FETCH_ERROR);
		}
		if (n != data->cur) {
			log_warnx("%s: bad message index: %s", a->name, line);
			return (FETCH_ERROR);
		}
		if (data->size == 0)
			return (FETCH_EMPTY);

		if (mail_open(m, IO_ROUND(data->size)) != 0) {
			log_warn("%s: failed to create mail", a->name);
			return (FETCH_ERROR);
		}
		m->size = 0;

		aux = xmalloc(sizeof *aux);
		aux->idx = data->cur;
		aux->uid = data->uid;
		m->auxdata = aux;
		m->auxfree = imap_free;

		default_tags(&m->tags, data->server.host, a);
		if (data->server.host != NULL) {
			add_tag(&m->tags, "server", "%s", data->server.host);
			add_tag(&m->tags, "port", "%s", data->server.port);
		}
		add_tag(&m->tags, "server_uid", "%u", data->uid);
		add_tag(&m->tags, "folder", "%s", data->folder);

		data->flushing = data->size > conf.max_size;
		data->lines = 0;
		data->bodylines = -1;

		data->state = IMAP_LINE;
		break;
	case IMAP_LINE:
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
		if (m->size + data->lines >= data->size)
			data->state = IMAP_END1;
		break;
	case IMAP_END1:
		if (strcmp(line, ")") != 0) {
			log_warnx("%s: invalid response: %s", a->name, line);
			return (FETCH_ERROR);
		}
		data->state = IMAP_END2;
		break;
	case IMAP_END2:
		if (!imap_okay(a, line))
			return (FETCH_ERROR);
		goto complete;
	}

	goto restart;

complete:
	data->state = IMAP_START;

	if (m->size + data->lines != data->size) {
		log_warnx("%s: received too much data", a->name);
		return (FETCH_ERROR);
	}

	add_tag(&m->tags, "lines", "%u", data->lines);
	if (data->bodylines == -1) {
		add_tag(&m->tags, "body_lines", "0");
		add_tag(&m->tags, "header_lines", "%u",  data->lines - 1);
	} else {
		add_tag(&m->tags, "body_lines", "%d", data->bodylines - 1);
		add_tag(&m->tags, "header_lines", "%d", data->lines -
		    data->bodylines);
	}

	if (data->flushing)
		return (FETCH_OVERSIZE);
	return (FETCH_SUCCESS);
}

int
imap_done(struct account *a, struct mail *m)
{
	struct fetch_imap_data	*data = a->data;
	struct fetch_imap_mail	*aux = m->auxdata;
	char			*line;

	if (m->decision == DECISION_KEEP) {
		ARRAY_ADD(&data->kept, aux->uid);
		return (FETCH_SUCCESS);
	}

	if (imap_putln(a,
	    "%u STORE %u +FLAGS \\Deleted", ++data->tag, aux->idx) != 0)
		return (FETCH_ERROR);
	if (imap_pollln(a, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (!imap_okay(a, line))
		return (FETCH_ERROR);

	return (FETCH_SUCCESS);
}

int
imap_purge(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_putln(a, "%u EXPUNGE", ++data->tag) != 0)
		return (FETCH_ERROR);
	if (imap_pollln(a, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (!imap_okay(a, line))
		return (FETCH_ERROR);

	if (imap_select(a) != 0)
		return (FETCH_ERROR);

	return (FETCH_SUCCESS);
}
#endif
