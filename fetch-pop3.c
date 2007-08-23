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

#include <openssl/md5.h>

#include "fdm.h"
#include "fetch.h"

void	fetch_pop3_fill(struct account *, struct iolist *);
int	fetch_pop3_commit(struct account *, struct mail *);
void	fetch_pop3_abort(struct account *);
u_int	fetch_pop3_total(struct account *);
void	fetch_pop3_desc(struct account *, char *, size_t);

void	fetch_pop3_free(void *);
int	fetch_pop3_okay(const char *);

int	fetch_pop3_bad(struct account *, const char *);
int	fetch_pop3_invalid(struct account *, const char *);

int	fetch_pop3_state_init(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_connect(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_connected(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_user(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_stat(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_first(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_next(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_delete(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_purge(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_reconnect(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_list(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_uidl(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_retr(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_line(struct account *, struct fetch_ctx *);
int	fetch_pop3_state_quit(struct account *, struct fetch_ctx *);
 
struct fetch fetch_pop3 = {
	"pop3",
	fetch_pop3_state_init,

	fetch_pop3_fill,
	fetch_pop3_commit,
	fetch_pop3_abort,
	fetch_pop3_total,
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

/* Fill io list. */
void
fetch_pop3_fill(struct account *a, struct iolist *iol)
{
	struct fetch_pop3_data	*data = a->data;

	ARRAY_ADD(iol, data->io);
}

/* Commit mail. */
int
fetch_pop3_commit(struct account *a, struct mail *m)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux = m->auxdata;

	if (m->decision == DECISION_DROP) {
		TAILQ_INSERT_TAIL(&data->dropped, aux, entry);
	} else {
		ARRAY_ADD(&data->kept, aux->uid);
		xfree(aux);

		data->committed++;
	}
	m->auxdata = m->auxfree = NULL;

	return (FETCH_AGAIN);
}

/* Close and free everything. Used for abort and after quit. */
void
fetch_pop3_abort(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	u_int			 i;

	if (data->io != NULL) {
		io_close(data->io);
		io_free(data->io);
		data->io = NULL;
	}

	while (!TAILQ_EMPTY(&data->dropped)) {
		aux = TAILQ_FIRST(&data->dropped);
		TAILQ_REMOVE(&data->dropped, aux, entry);
		fetch_pop3_free(aux);

	}

	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++)
		xfree(ARRAY_ITEM(&data->kept, i));
	ARRAY_FREE(&data->kept);
}

/* Return total mails. */
u_int
fetch_pop3_total(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	return (data->total);
}

/*
 * Initial state. This is separate from connect as it is necessary to reconnect
 * without wiping the dropped/kept list and counters.
 */
int
fetch_pop3_state_init(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;

 	TAILQ_INIT(&data->dropped);
 	ARRAY_INIT(&data->kept);

	data->total = data->committed = 0;

	fctx->state = fetch_pop3_state_connect;
	return (FETCH_AGAIN);
}

/* Connect state. */
int
fetch_pop3_state_connect(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*cause;

	data->io = connectproxy(&data->server,
	    conf.verify_certs, conf.proxy, IO_CRLF, conf.timeout, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	fctx->state = fetch_pop3_state_connected;
	return (FETCH_BLOCK);
}

/* Connected state: wait for initial +OK line from server. */
int
fetch_pop3_state_connected(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line, *ptr, *src;
	char			 out[MD5_DIGEST_LENGTH * 2 + 1];
	u_char			 digest[MD5_DIGEST_LENGTH];
	u_int			 i;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	if (data->apop && (line = strchr(line, '<')) != NULL) {
		if ((ptr = strchr(line + 1, '>')) != NULL) {
			*++ptr = '\0';

			xasprintf(&src, "%s%s", line, data->pass);
			MD5(src, strlen(src), digest);
			xfree(src);
			
			for (i = 0; i < MD5_DIGEST_LENGTH; i++)
				xsnprintf(out + i * 2, 3, "%02hhx", digest[i]);

			io_writeline(data->io, "APOP %s %s", data->user, out);
			fctx->state = fetch_pop3_state_stat;
			return (FETCH_BLOCK);
		}
	}

	io_writeline(data->io, "USER %s", data->user);
	fctx->state = fetch_pop3_state_user;
	return (FETCH_BLOCK);
}

/* User state. */
int
fetch_pop3_state_user(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	io_writeline(data->io, "PASS %s", data->pass);
	fctx->state = fetch_pop3_state_stat;
	return (FETCH_BLOCK);
}

/* Stat state. */
int
fetch_pop3_state_stat(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	io_writeline(data->io, "STAT");
	fctx->state = fetch_pop3_state_first;
	return (FETCH_BLOCK);
}

/* First state. Wait for +OK then switch to get first mail. */
int
fetch_pop3_state_first(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	if (sscanf(line, "+OK %u %*u", &data->num) != 1)
		return (fetch_pop3_invalid(a, line));
	data->cur = 0;

	/* Save total, if zero (could be reconnect after purge). */
	if (data->total == 0)
		data->total = data->num;

	/* If polling, stop here. */
	if (fctx->flags & FETCH_POLL) {
		io_writeline(data->io, "QUIT");
		fctx->state = fetch_pop3_state_quit;
		return (FETCH_BLOCK);
	}

	fctx->state = fetch_pop3_state_next;
	return (FETCH_AGAIN);
}

/* Next state. */
int
fetch_pop3_state_next(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;

	/* Handle dropped mail here. */
	if (!TAILQ_EMPTY(&data->dropped)) {
		aux = TAILQ_FIRST(&data->dropped);
		
		io_writeline(data->io, "DELE %u", aux->idx);
		fctx->state = fetch_pop3_state_delete;
		return (FETCH_BLOCK);
	}

	/*
	 * Switch to purge state if requested. This must be after dropped
	 * mail is flushed otherwise it might use the wrong indexes after
	 * reconnect.
	 */
	if (fctx->flags & FETCH_PURGE) {
		fctx->state = fetch_pop3_state_purge;
		return (FETCH_AGAIN);
	}

	/* Move to next mail if possible. */
	if (data->cur <= data->num)
		data->cur++;

	/* 
	 * If this is the last mail, wait until everything has been committed
	 * back, then quit.
	 */
	if (data->cur > data->num) {
		if (data->committed != data->total)
			return (FETCH_BLOCK);
		io_writeline(data->io, "QUIT");
		fctx->state = fetch_pop3_state_quit;
		return (FETCH_BLOCK);
	}

	/* List the next mail. */
	io_writeline(data->io, "LIST %u", data->cur);
	fctx->state = fetch_pop3_state_list;
	return (FETCH_BLOCK);
}

/* Delete state. */
int
fetch_pop3_state_delete(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	char			*line;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	aux = TAILQ_FIRST(&data->dropped);
	TAILQ_REMOVE(&data->dropped, aux, entry);
	fetch_pop3_free(aux);

	data->committed++;

	fctx->state = fetch_pop3_state_next;
	return (FETCH_AGAIN);
}

/* Purge state. Purge mail if required. */
int
fetch_pop3_state_purge(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;

	if (fctx->flags & FETCH_EMPTY) {
		fctx->flags &= ~FETCH_PURGE;

		io_writeline(data->io, "QUIT");
		fctx->state = fetch_pop3_state_reconnect;
	}
	return (FETCH_BLOCK);
}

/* Reconnect state. */
int
fetch_pop3_state_reconnect(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	io_close(data->io);
	io_free(data->io);
	data->io = NULL;

	fctx->state = fetch_pop3_state_connect;
	return (FETCH_AGAIN);
}

/* List state. */
int
fetch_pop3_state_list(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
	struct fetch_pop3_mail	*aux;
	char			*line;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	if (sscanf(line, "+OK %*u %zu", &data->size) != 1)
		return (fetch_pop3_invalid(a, line));

	/* Fill in local data. */
	aux = xcalloc(1, sizeof *aux);
	aux->idx = data->cur;
	m->auxdata = aux;
	m->auxfree = fetch_pop3_free;

	io_writeline(data->io, "UIDL %u", data->cur);
	fctx->state = fetch_pop3_state_uidl;
	return (FETCH_BLOCK);
}

/* UIDL state. Get and save the UID. */
int
fetch_pop3_state_uidl(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
 	struct fetch_pop3_mail	*aux;
	char			*line, *ptr;
	u_int			 n, i;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	if (sscanf(line, "+OK %u ", &n) != 1)
		return (fetch_pop3_bad(a, line));
	if (n != data->cur)
		return (fetch_pop3_bad(a, line));

	ptr = strchr(line, ' ');
	if (ptr == NULL)
		return (fetch_pop3_bad(a, line));
	ptr = strchr(ptr + 1, ' ');
	if (ptr == NULL)
		return (fetch_pop3_bad(a, line));

	aux = m->auxdata;
	aux->uid = xstrdup(ptr + 1);
	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
		if (strcmp(aux->uid, ARRAY_ITEM(&data->kept, i)) == 0) {
			/*
			 * Seen this message before and kept it, so skip it
			 * this time.
			 */
			fctx->state = fetch_pop3_state_next;
			return (FETCH_AGAIN);
		}
	}

	io_writeline(data->io, "RETR %u", data->cur);
	fctx->state = fetch_pop3_state_retr;
	return (FETCH_BLOCK);
}

/* Retr state. */
int
fetch_pop3_state_retr(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
 	struct fetch_pop3_mail	*aux = m->auxdata;
	char			*line;

	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	/* Open the mail. */
	if (mail_open(m, data->size) != 0) {
		log_warn("%s: failed to create mail", a->name);
		return (FETCH_ERROR);
	}
	m->size = 0;

	/* Tag mail. */
	default_tags(&m->tags, data->server.host);
	add_tag(&m->tags, "server", "%s", data->server.host);
	add_tag(&m->tags, "port", "%s", data->server.port);
	add_tag(&m->tags, "server_uid", "%s", aux->uid);

	data->flushing = 0;

	fctx->state = fetch_pop3_state_line;
	return (FETCH_AGAIN);
}

/* Line state. */
int
fetch_pop3_state_line(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
	char			*line;

	for (;;) {
		line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
		if (line == NULL)
			return (FETCH_BLOCK);
		
		if (line[0] == '.') {
			if (line[1] == '\0')
				break;
			line++;
		}
		
		if (data->flushing)
			continue;
		
		if (append_line(m, line, strlen(line)) != 0) {
			log_warn("%s: failed to resize mail", a->name);
			return (FETCH_ERROR);
		}
		if (m->size > conf.max_size)
			data->flushing = 1;
	}

	fctx->state = fetch_pop3_state_next;
	return (FETCH_MAIL);
}

/* Quit state. */
int
fetch_pop3_state_quit(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;
	
	line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!fetch_pop3_okay(line))
		return (fetch_pop3_bad(a, line));

	fetch_pop3_abort(a);
	return (FETCH_EXIT);
}

void
fetch_pop3_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_pop3_data	*data = a->data;

	xsnprintf(buf, len, "pop3%s server \"%s\" port %s user \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->user);
}
