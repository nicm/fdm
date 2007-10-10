/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/md5.h>

#include "fdm.h"
#include "fetch.h"

int	pop3_putln(struct account *, const char *, ...);
int	pop3_getln(struct account *, struct fetch_ctx *, char **);

int	pop3_commit(struct account *, struct mail *);
void	pop3_abort(struct account *);
u_int	pop3_total(struct account *);

int	pop3_load(struct account *);
int	pop3_save(struct account *);

int	pop3_cmp(struct fetch_pop3_mail *, struct fetch_pop3_mail *);
void	pop3_free(void *);
int	pop3_okay(const char *);

void	pop3_freequeue(struct fetch_pop3_queue *);
void	pop3_freetree(struct fetch_pop3_tree *);

int	pop3_bad(struct account *, const char *);
int	pop3_invalid(struct account *, const char *);

int	pop3_state_connect(struct account *, struct fetch_ctx *);
int	pop3_state_connected(struct account *, struct fetch_ctx *);
int	pop3_state_user(struct account *, struct fetch_ctx *);
int	pop3_state_cache1(struct account *, struct fetch_ctx *);
int	pop3_state_cache2(struct account *, struct fetch_ctx *);
int	pop3_state_cache3(struct account *, struct fetch_ctx *);
int	pop3_state_stat(struct account *, struct fetch_ctx *);
int	pop3_state_first(struct account *, struct fetch_ctx *);
int	pop3_state_next(struct account *, struct fetch_ctx *);
int	pop3_state_delete(struct account *, struct fetch_ctx *);
int	pop3_state_reconnect(struct account *, struct fetch_ctx *);
int	pop3_state_list(struct account *, struct fetch_ctx *);
int	pop3_state_uidl(struct account *, struct fetch_ctx *);
int	pop3_state_retr(struct account *, struct fetch_ctx *);
int	pop3_state_line(struct account *, struct fetch_ctx *);
int	pop3_state_quit(struct account *, struct fetch_ctx *);

SPLAY_PROTOTYPE(fetch_pop3_tree, fetch_pop3_mail, tentry, pop3_cmp);
SPLAY_GENERATE(fetch_pop3_tree, fetch_pop3_mail, tentry, pop3_cmp);

/* Put line to server. */
int
pop3_putln(struct account *a, const char *fmt, ...)
{
	struct fetch_pop3_data	*data = a->data;
	va_list			 ap;
	int			 n;

	va_start(ap, fmt);
	n = data->putln(a, fmt, ap);
	va_end(ap);

	return (n);
}

/* Get line from server. Returns -1 on error, a NULL line if out of data. */
int
pop3_getln(struct account *a, struct fetch_ctx *fctx, char **line)
{
	struct fetch_pop3_data	*data = a->data;

	if (data->getln(a, fctx, line) != 0)
		return (-1);
	return (0);
}

int
pop3_cmp(struct fetch_pop3_mail *aux1, struct fetch_pop3_mail *aux2)
{
	return (strcmp(aux1->uid, aux2->uid));
}

/*
 * Free a POP3 mail aux structure. All such structures are always on at least
 * one queue or tree so this is always called explicitly rather than via the
 * mail auxfree member.
 */
void
pop3_free(void *ptr)
{
	struct fetch_pop3_mail	*aux = ptr;

	if (aux->uid != NULL)
		xfree(aux->uid);
	xfree(aux);
}

int
pop3_okay(const char *line)
{
	return (strncmp(line, "+OK", 3) == 0);
}

void
pop3_freequeue(struct fetch_pop3_queue *q)
{
	struct fetch_pop3_mail	*aux;

	while (!TAILQ_EMPTY(q)) {
		aux = TAILQ_FIRST(q);
		TAILQ_REMOVE(q, aux, qentry);
		pop3_free(aux);
	}
}

void
pop3_freetree(struct fetch_pop3_tree *t)
{
	struct fetch_pop3_mail	*aux;

	while (!SPLAY_EMPTY(t)) {
		aux = SPLAY_ROOT(t);
		SPLAY_REMOVE(fetch_pop3_tree, t, aux);
		pop3_free(aux);
	}
}

int
pop3_bad(struct account *a, const char *line)
{
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (FETCH_ERROR);
}

int
pop3_invalid(struct account *a, const char *line)
{
	log_warnx("%s: invalid response: %s", a->name, line);
	return (FETCH_ERROR);
}

/* Load POP3 cache file into the cache queue. */
int
pop3_load(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	int			 fd;
	FILE			*f = NULL;
	char			*uid;
	size_t			 uidlen;
	u_int			 n;

	if (data->path == NULL)
		return (0);

	if ((fd = openlock(data->path, O_RDONLY, conf.lock_types)) == -1) {
		if (errno == ENOENT)
			return (0);
		log_warn("%s: %s", a->name, data->path);
		goto error;
	}
	if ((f = fdopen(fd, "r")) == NULL) {
		log_warn("%s: %s", a->name, data->path);
		goto error;
	}

	n = 0;
	for (;;) {
		if (fscanf(f, "%zu ", &uidlen) != 1) {
			/* EOF is allowed only at the start of a line. */
			if (feof(f))
				break;
			goto invalid;
		}
		uid = xmalloc(uidlen + 1);
		if (fread(uid, uidlen, 1, f) != 1)
			goto invalid;
		uid[uidlen] = '\0';

		log_debug3("%s: found UID in cache: %s", a->name, uid);

		aux = xcalloc(1, sizeof *aux);
		aux->uid = uid;
		SPLAY_INSERT(fetch_pop3_tree, &data->cacheq, aux);
	}

	fclose(f);
	closelock(fd, data->path, conf.lock_types);
	return (0);

invalid:
	log_warnx("%s: invalid cache entry", a->name);

error:
	if (f != NULL)
		fclose(f);
        if (fd != -1)
		closelock(fd, data->path, conf.lock_types);
	return (-1);
}

/* Save POP3 cache file. */
int
pop3_save(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	char			*path = NULL, tmp[MAXPATHLEN];
	int			 fd = -1;
	FILE			*f = NULL;
	u_int			 n;

	if (data->path == NULL)
		return (0);

	if (mkpath(tmp, sizeof tmp, "%s.XXXXXXXXXX", data->path) != 0)
		goto error;
	if ((fd = mkstemp(tmp)) == -1)
		goto error;
	path = tmp;
	cleanup_register(path);

	if ((f = fdopen(fd, "r+")) == NULL)
		goto error;
	fd = -1;

	n = 0;
	SPLAY_FOREACH(aux, fetch_pop3_tree, &data->cacheq) {
		fprintf(f, "%zu %s\n", strlen(aux->uid), aux->uid);
		n++;
	}
	log_debug2("%s: saved cache %s: %u entries", a->name, data->path, n);

	if (fflush(f) != 0)
		goto error;
	if (fsync(fileno(f)) != 0)
		goto error;
	fclose(f);
	f = NULL;

	if (rename(path, data->path) == -1)
		goto error;
	cleanup_deregister(path);
	return (0);

error:
	log_warn("%s: %s", a->name, data->path);

	if (f != NULL)
		fclose(f);
	if (fd != -1)
		close(fd);

	if (path != NULL) {
		if (unlink(tmp) != 0)
			fatal("unlink failed");
		cleanup_deregister(path);
	}
	return (-1);
}

/* Commit mail. */
int
pop3_commit(struct account *a, struct mail *m)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux = m->auxdata;

	if (m->decision == DECISION_DROP) {
		/* Insert to tail of the drop queue; reading is from head. */
		TAILQ_INSERT_TAIL(&data->dropq, aux, qentry);
		m->auxdata = NULL;
	} else {
		/* If not already in the cache, add it. */
		if (SPLAY_FIND(fetch_pop3_tree, &data->cacheq, aux) == NULL)
			SPLAY_INSERT(fetch_pop3_tree, &data->cacheq, aux);
		else
			pop3_free(aux);
		m->auxdata = NULL;

		data->committed++;
		if (data->only != FETCH_ONLY_OLD && pop3_save(a) != 0)
			return (FETCH_ERROR);
	}

	return (FETCH_AGAIN);
}

/* Close and free everything. Used for abort and after quit. */
void
pop3_abort(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	pop3_freetree(&data->serverq);
	pop3_freetree(&data->cacheq);
	pop3_freequeue(&data->wantq);
	pop3_freequeue(&data->dropq);

	data->disconnect(a);
}

/* Return total mails. */
u_int
pop3_total(struct account *a)
{
	struct fetch_pop3_data	*data = a->data;

	return (data->total);
}

/*
 * Initial state. This is separate from connect as it is necessary to reconnect
 * without wiping the dropped/kept list and counters.
 */
int
pop3_state_init(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;

	SPLAY_INIT(&data->serverq);
	SPLAY_INIT(&data->cacheq);
	TAILQ_INIT(&data->wantq);
	TAILQ_INIT(&data->dropq);

	data->total = data->committed = 0;

	fctx->state = pop3_state_connect;
	return (FETCH_AGAIN);
}

/* Connect state. */
int
pop3_state_connect(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;

	if (data->connect(a) != 0)
		return (FETCH_ERROR);

	fctx->state = pop3_state_connected;
	return (FETCH_BLOCK);
}

/* Connected state: wait for initial +OK line from server. */
int
pop3_state_connected(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line, *ptr, *src;
	char			 out[MD5_DIGEST_LENGTH * 2 + 1];
	u_char			 digest[MD5_DIGEST_LENGTH];
	u_int			 i;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	if (data->apop && (line = strchr(line, '<')) != NULL) {
		if ((ptr = strchr(line + 1, '>')) != NULL) {
			*++ptr = '\0';

			xasprintf(&src, "%s%s", line, data->pass);
			MD5(src, strlen(src), digest);
			xfree(src);

			for (i = 0; i < MD5_DIGEST_LENGTH; i++)
				xsnprintf(out + i * 2, 3, "%02hhx", digest[i]);

			if (pop3_putln(a, "APOP %s %s", data->user, out) != 0)
				return (FETCH_ERROR);
			fctx->state = pop3_state_stat;
			return (FETCH_BLOCK);
		}
	}

	if (pop3_putln(a, "USER %s", data->user) != 0)
		return (FETCH_ERROR);
	fctx->state = pop3_state_user;
	return (FETCH_BLOCK);
}

/* User state. */
int
pop3_state_user(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	if (pop3_putln(a, "PASS %s", data->pass) != 0)
		return (FETCH_ERROR);
	fctx->state = pop3_state_stat;
	return (FETCH_BLOCK);
}

/* Stat state. */
int
pop3_state_stat(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	if (pop3_putln(a, "STAT") != 0)
		return (FETCH_ERROR);
	fctx->state = pop3_state_first;
	return (FETCH_BLOCK);
}

/* First state. Wait for +OK then switch to get first mail. */
int
pop3_state_first(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;
	u_int			 n;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	if (sscanf(line, "+OK %u %u", &data->num, &n) != 2)
		return (pop3_invalid(a, line));
	data->cur = 0;

	/*
	 * If no mail, we can skip UIDL and either quit (if polling or not
	 * reconnecting) or skip to wait in next state.
	 */
	if (data->num == 0) {
		if (data->total != 0) {
			fctx->state = pop3_state_next;
			return (FETCH_AGAIN);
		}
		if (pop3_putln(a, "QUIT") != 0)
			return (FETCH_ERROR);
		fctx->state = pop3_state_quit;
		return (FETCH_BLOCK);
	}

	if (pop3_putln(a, "UIDL") != 0)
		return (FETCH_ERROR);
	fctx->state = pop3_state_cache1;
	return (FETCH_BLOCK);
}

/* Cache state 1. */
int
pop3_state_cache1(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	/* Free the server queue. */
	pop3_freetree(&data->serverq);

	fctx->state = pop3_state_cache2;
	return (FETCH_AGAIN);
}

/* Cache state 2. */
int
pop3_state_cache2(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	char			*line, *ptr;
	u_int			 n;

	/* Parse response and add to server queue. */
	while (data->cur != data->num) {
		if (pop3_getln(a, fctx, &line) != 0)
			return (FETCH_ERROR);
		if (line == NULL)
			return (FETCH_BLOCK);

		if (sscanf(line, "%u %*s", &n) != 1)
			return (pop3_invalid(a, line));
		if (n != data->cur + 1)
			return (pop3_bad(a, line));
		line = strchr(line, ' ') + 1;

		/* 
		 * Check UID validity. We are intolerant about validity since
		 * accepting bad UIDs could potentially end up with UIDs that
		 * conflict.
		 */
		if (*line == '\0') {
			log_warnx("%s: empty UID", a->name);
			return (FETCH_ERROR);
		}
		for (ptr = line; *ptr != '\0'; ptr++) {
			if (*ptr < 0x21 || *ptr > 0x7e) {
				log_warnx("%s: invalid UID: %s", a->name, line);
				return (FETCH_ERROR);
			}
		}
		if (ptr > line + 70) {
				log_warnx("%s: UID too big: %s", a->name, line);
				return (FETCH_ERROR);
		}			

		aux = xcalloc(1, sizeof *aux);
		aux->idx = n;
		aux->uid = xstrdup(line);

		/*
		 * If this is already in the queue, the mailbox has multiple
		 * identical messages. This is one of the more stupid aspects
		 * of the POP3 protocol (a unique id that isn't unique? great!).
		 * At the moment we just abort with an error.
		 * XXX what can we do to about this?
		 */
		if (SPLAY_FIND(fetch_pop3_tree, &data->serverq, aux)) {
			xfree(aux);
			log_warnx("%s: UID collision: %s", a->name, line);
			return (FETCH_ERROR);
		}

		SPLAY_INSERT(fetch_pop3_tree, &data->serverq, aux);
		data->cur++;
	}

	fctx->state = pop3_state_cache3;
	return (FETCH_AGAIN);
}

/* Cache state 3. */
int
pop3_state_cache3(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux1, *aux2, *aux3;
	char			*line;
	u_int			 n;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (line[0] != '.' && line[1] != '\0')
		return (pop3_bad(a, line));

	/*
	 * Resolve the caches.
	 *
	 * At this point: serverq holds a list of all mails on the server and
	 * their indexes; cacheq holds a list of all mails in the cache file; if
	 * connecting for the first time, wantq is empty, otherwise it has the
	 * list of mails we want.
	 */
	n = 0;
	if (data->total == 0) {
		/*
		 * If not reconnecting, build the wantq list based on the
		 * serverq and the cache.
		 */

		/* Load the cache and weed out any mail that doesn't exist. */
		if (pop3_load(a) != 0)
			return (FETCH_ERROR);
		aux1 = SPLAY_MIN(fetch_pop3_tree, &data->cacheq);
		while (aux1 != NULL) {
			aux2 = aux1;
			aux1 = SPLAY_NEXT(fetch_pop3_tree, &data->cacheq, aux1);

			if (SPLAY_FIND(
			    fetch_pop3_tree, &data->serverq, aux2) != NULL)
				continue;
			SPLAY_REMOVE(fetch_pop3_tree, &data->cacheq, aux2);
			pop3_free(aux2);
		}

		/* Build the want queue from the server queue. */
		SPLAY_FOREACH(aux1, fetch_pop3_tree, &data->serverq) {
			switch (data->only) {
			case FETCH_ONLY_ALL:
				/* Get all mails. */
				break;
			case FETCH_ONLY_NEW:
				/* Get only mails not in the cache. */
				if (SPLAY_FIND(fetch_pop3_tree,
				    &data->cacheq, aux1) != NULL)
					continue;
				break;
			case FETCH_ONLY_OLD:
				/* Get only mails in the cache. */
				if (SPLAY_FIND(fetch_pop3_tree,
				    &data->cacheq, aux1) == NULL)
					continue;
				break;
			}

			/* Copy the mail to the want queue. */
			aux2 = xcalloc(1, sizeof *aux2);
			aux2->idx = aux1->idx;
			aux2->uid = xstrdup(aux1->uid);
			TAILQ_INSERT_TAIL(&data->wantq, aux2, qentry);
			data->total++;
		}

		/*
		 * If there are no actual mails to fetch now, or if polling,
		 * stop.
		 */
		if (data->total == 0 || fctx->flags & FETCH_POLL) {
			if (pop3_putln(a, "QUIT") != 0)
				return (FETCH_ERROR);
			fctx->state = pop3_state_quit;
			return (FETCH_BLOCK);
		}
	} else {
		/*
		 * Reconnecting. The want queue already exists but the
		 * indexes need to be updated from the server queue.
		 */
		aux1 = TAILQ_FIRST(&data->wantq);
		while (aux1 != NULL) {
			aux2 = aux1;
			aux1 = TAILQ_NEXT(aux1, qentry);

			/*
			 * Check the server queue. Mails now not on the server
			 * are removed.
			 */
			aux3 = SPLAY_FIND(
			    fetch_pop3_tree, &data->serverq, aux2);
			if (aux3 == NULL) {
				TAILQ_REMOVE(&data->wantq, aux2, qentry);
				pop3_free(aux2);
				data->total--;
			} else
				aux2->idx = aux3->idx;
		}
	}

	fctx->state = pop3_state_next;
	return (FETCH_AGAIN);
}

/* Next state. */
int
pop3_state_next(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
	struct fetch_pop3_mail	*aux;

	/* Handle dropped mail here. */
	if (!TAILQ_EMPTY(&data->dropq)) {
		aux = TAILQ_FIRST(&data->dropq);

		if (pop3_putln(a, "DELE %u", aux->idx) != 0)
			return (FETCH_ERROR);
		fctx->state = pop3_state_delete;
		return (FETCH_BLOCK);
	}

	/*
	 * If no more mail, wait until everything has been committed, then
	 * quit.
	 */
	if (TAILQ_EMPTY(&data->wantq)) {
		if (data->committed != data->total)
			return (FETCH_BLOCK);

		if (pop3_putln(a, "QUIT") != 0)
			return (FETCH_ERROR);
		fctx->state = pop3_state_quit;
		return (FETCH_BLOCK);
	}

	/*
	 * Try to purge if requested. This must be after dropped mail is
	 * flushed otherwise it might use the wrong indexes after reconnect.
	 */
	if (fctx->flags & FETCH_PURGE) {
		/*
		 * If can't purge now, loop through this state not fetching
		 * mail until we can: there is no mail on the dropped queue,
		 * and FETCH_EMPTY is set. Used to have a seperate state to
		 * loop through without returning here, but that is wrong:
		 * mail could potentially be added to the dropped list while
		 * in that state.
		 */
		if (fctx->flags & FETCH_EMPTY) {
			fctx->flags &= ~FETCH_PURGE;

			if (pop3_putln(a, "QUIT") != 0)
				return (FETCH_ERROR);
			fctx->state = pop3_state_reconnect;
			return (FETCH_BLOCK);
		}

		/*
		 * Must be waiting for delivery, so permit blocking even though
		 * we (fetch) aren't waiting for any data.
		 */
		return (FETCH_BLOCK);
	}

	/* Find the next mail. */
	aux = TAILQ_FIRST(&data->wantq);
	m->auxdata = aux;

	/* And list it. */
	if (pop3_putln(a, "LIST %u", aux->idx) != 0)
		return (FETCH_ERROR);
	fctx->state = pop3_state_list;
	return (FETCH_BLOCK);
}

/* Delete state. */
int
pop3_state_delete(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct fetch_pop3_mail	*aux;
	char			*line;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	aux = TAILQ_FIRST(&data->dropq);

	/* Remove from the drop queue. */
	TAILQ_REMOVE(&data->dropq, aux, qentry);

	/* If not already in the cache, add it. */
	if (SPLAY_FIND(fetch_pop3_tree, &data->cacheq, aux) == NULL)
		SPLAY_INSERT(fetch_pop3_tree, &data->cacheq, aux);
	else
		pop3_free(aux);

	/* Update counter and save the cache. */
	data->committed++;
	if (data->only != FETCH_ONLY_OLD && pop3_save(a) != 0)
		return (FETCH_ERROR);

	fctx->state = pop3_state_next;
	return (FETCH_AGAIN);
}

/* Reconnect state. */
int
pop3_state_reconnect(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	char			*line;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	data->disconnect(a);

	fctx->state = pop3_state_connect;
	return (FETCH_AGAIN);
}

/* List state. */
int
pop3_state_list(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
	struct fetch_pop3_mail	*aux = m->auxdata;
	char			*line;
	u_int			 n;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	if (sscanf(line, "+OK %u %zu", &n, &data->size) != 1)
		return (pop3_invalid(a, line));
	if (n != aux->idx)
		return (pop3_bad(a, line));

	if (pop3_putln(a, "RETR %u", aux->idx) != 0)
		return (FETCH_ERROR);
	fctx->state = pop3_state_retr;
	return (FETCH_BLOCK);
}

/* Retr state. */
int
pop3_state_retr(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
 	struct fetch_pop3_mail	*aux = m->auxdata;
	char			*line;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	/* Open the mail. */
	if (mail_open(m, data->size) != 0) {
		log_warn("%s: failed to create mail", a->name);
		return (FETCH_ERROR);
	}
	m->size = 0;

	/* Tag mail. */
	default_tags(&m->tags, data->src);
	if (data->server.host != NULL) {
		add_tag(&m->tags, "server", "%s", data->server.host);
		add_tag(&m->tags, "port", "%s", data->server.port);
	}
	add_tag(&m->tags, "server_uid", "%s", aux->uid);

	data->flushing = 0;

	fctx->state = pop3_state_line;
	return (FETCH_AGAIN);
}

/* Line state. */
int
pop3_state_line(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_pop3_data	*data = a->data;
	struct mail		*m = fctx->mail;
	struct fetch_pop3_mail	*aux = m->auxdata;
	char			*line;

	for (;;) {
		if (pop3_getln(a, fctx, &line) != 0)
			return (FETCH_ERROR);
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

	/* Pull from the want queue. */
	TAILQ_REMOVE(&data->wantq, aux, qentry);

	fctx->state = pop3_state_next;
	return (FETCH_MAIL);
}

/* Quit state. */
int
pop3_state_quit(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (pop3_getln(a, fctx, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!pop3_okay(line))
		return (pop3_bad(a, line));

	pop3_abort(a);
	return (FETCH_EXIT);
}
