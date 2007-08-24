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
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

void	fetch_nntp_fill(struct account *, struct iolist *);
void	fetch_nntp_abort(struct account *);
u_int	fetch_nntp_total(struct account *);
void	fetch_nntp_desc(struct account *, char *, size_t);

int	fetch_nntp_code(char *);
int	fetch_nntp_check(
	    struct account *, struct fetch_ctx *, char **, int *, u_int, ...);
int	fetch_nntp_parse223(char *, u_int *, char **);

int	fetch_nntp_load(struct account *);
int	fetch_nntp_save(struct account *);

int	fetch_nntp_bad(struct account *, const char *);
int	fetch_nntp_invalid(struct account *, const char *);

int	fetch_nntp_state_connect(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_connected(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_switch(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_group(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_reset(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_stat(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_wait(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_next(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_article(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_line(struct account *, struct fetch_ctx *);
int	fetch_nntp_state_quit(struct account *, struct fetch_ctx *);

struct fetch fetch_nntp = {
	"nntp",
	fetch_nntp_state_connect,

	fetch_nntp_fill,
	NULL,
	fetch_nntp_abort,
	NULL,
	fetch_nntp_desc
};

int
fetch_nntp_bad(struct account *a, const char *line)
{
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (FETCH_ERROR);
}

int
fetch_nntp_invalid(struct account *a, const char *line)
{
	log_warnx("%s: invalid response: %s", a->name, line);
	return (FETCH_ERROR);
}

/* Extract code from line. */
int
fetch_nntp_code(char *line)
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

/*
 * Get line from server and check against list of codes.  Returns -1 on error,
 * 0 on success, a NULL line when out of data.
 */
int
fetch_nntp_check(struct account *a,
    struct fetch_ctx *fctx, char **line, int *codep, u_int n, ...)
{
	struct fetch_nntp_data	*data = a->data;
	va_list			 ap;
	u_int			 i;
	int			 code;

	if (codep == NULL)
		codep = &code;

	do {
		*line = io_readline2(data->io, &fctx->lbuf, &fctx->llen);
		if (*line == NULL)
			return (0);

		*codep = fetch_nntp_code(*line);
		if (*codep == -1)
			goto error;
	} while (*codep >= 100 && *codep <= 199);

	va_start(ap, n);
	for (i = n; i > 0; i--) {
		if (*codep == va_arg(ap, int))
			break;
	}
	va_end(ap);
	if (i == 0)
		goto error;

	return (0);

error:
	log_warnx("%s: unexpected data: %s", a->name, *line);
	return (-1);
}

/* Extract id from 223 code. */
int
fetch_nntp_parse223(char *line, u_int *n, char **id)
{
	char	*ptr, *ptr2;

	if (sscanf(line, "223 %u ", n) != 1)
		return (-1);

	ptr = strchr(line, '<');
	if (ptr == NULL)
		return (1);
	ptr2 = strchr(ptr, '>');
	if (ptr2 == NULL)
		return (-1);
	ptr++;

	*id = xmalloc(ptr2 - ptr + 1);
	memcpy(*id, ptr, ptr2 - ptr);
	(*id)[ptr2 - ptr] = '\0';

	return (0);
}

/* Load NNTP cache file. */
int
fetch_nntp_load(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	int			 fd;
	FILE			*f;
	char			*name, *id;
	size_t			 namelen, idlen;
	u_int			 last, i;

	f = NULL;

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

	for (;;) {
		if (fscanf(f, "%zu ", &namelen) != 1) {
			/* EOF is allowed only at the start of a line. */
			if (feof(f))
				break;
			goto invalid;
		}
		name = xmalloc(namelen + 1);
		if (fread(name, namelen, 1, f) != 1)
			goto invalid;
		name[namelen] = '\0';

		if (fscanf(f, " %u ", &last) != 1)
			goto invalid;

		if (fscanf(f, "%zu ", &idlen) != 1)
			goto invalid;
		id = xmalloc(idlen + 1);
		if (fread(id, idlen, 1, f) != 1)
			goto invalid;
		id[idlen] = '\0';

		/* Got a group. Fill it in. */
		group = NULL;
		for (i = 0; i < ARRAY_LENGTH(&data->groups); i++) {
			group = ARRAY_ITEM(&data->groups, i);
			if (strcmp(group->name, name) == 0)
				break;
		}
		if (i == ARRAY_LENGTH(&data->groups)) {
			/*
			 * Not found. add it so it is saved when the file is
			 * resaved, but with ignore set so it isn't fetched.
			 */
			group = xcalloc(1, sizeof *group);
			ARRAY_ADD(&data->groups, group);
			group->ignore = 1;
			group->name = xstrdup(name);
		}
		log_debug2("%s: found group in cache: %s", a->name, name);

		group->last = last;
		group->id = id;
		xfree(name);
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

/* Save NNTP cache file. */
int
fetch_nntp_save(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	char			*path = NULL, tmp[MAXPATHLEN];
	int			 fd = -1;
	FILE			*f = NULL;
	u_int			 i;

	if (mkpath(tmp, sizeof tmp, "%s.XXXXXXXXXX", data->path) != 0)
		goto error;
	if ((fd = mkstemp(tmp)) == -1)
		goto error;
	path = tmp;
	cleanup_register(path);

	if ((f = fdopen(fd, "r+")) == NULL)
		goto error;
	fd = -1;

	for (i = 0; i < ARRAY_LENGTH(&data->groups); i++) {
		group = ARRAY_ITEM(&data->groups, i);
		if (group->id == NULL)
			continue;
		fprintf(f, "%zu %s %u %zu %s\n", strlen(group->name),
		    group->name, group->last, strlen(group->id), group->id);
	}

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

/* Fill io list. */
void
fetch_nntp_fill(struct account *a, struct iolist *iol)
{
	struct fetch_nntp_data	*data = a->data;

	if (data->io != NULL)
		ARRAY_ADD(iol, data->io);
}

/* Abort fetch and free everything. */
void
fetch_nntp_abort(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	u_int			 i;

	if (data->io != NULL) {
		io_close(data->io);
		io_free(data->io);
		data->io = NULL;
	}

	for (i = 0; i < ARRAY_LENGTH(&data->groups); i++) {
		group = ARRAY_ITEM(&data->groups, i);
		xfree(group->name);
		if (group->id != NULL)
			xfree(group->id);
		xfree(group);
	}
	ARRAY_FREE(&data->groups);
}

/* Connect to NNTP server. */
int
fetch_nntp_state_connect(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	u_int			 i;
	char			*cause;

	/* Initialise and load groups array. */
	ARRAY_INIT(&data->groups);
	for (i = 0; i < ARRAY_LENGTH(data->names); i++) {
		group = xcalloc(1, sizeof *group);
		group->name = xstrdup(ARRAY_ITEM(data->names, i));
		group->id = NULL;
		group->ignore = 0;
		ARRAY_ADD(&data->groups, group);
	}
	if (fetch_nntp_load(a) != 0)
		return (FETCH_ERROR);

	/* Find the first active group, if any. */
	data->group = 0;
	while (ARRAY_ITEM(&data->groups, data->group)->ignore) {
		data->group++;
		if (data->group == ARRAY_LENGTH(&data->groups)) {
			log_warnx("%s: no groups found", a->name);
			return (FETCH_ERROR);
		}
	}

	/* Connect to the server. */
	data->io = connectproxy(&data->server,
	    conf.verify_certs, conf.proxy, IO_CRLF, conf.timeout, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	fctx->state = fetch_nntp_state_connected;
	return (FETCH_BLOCK);
}

/* Connected state. */
int
fetch_nntp_state_connected(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (fetch_nntp_check(a, fctx, &line, NULL, 1, 200) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	fctx->state = fetch_nntp_state_group;
	return (FETCH_AGAIN);
}

/*
 * Switch to the next group. Missed out the first time since connect already
 * finds the first group.
 */
int
fetch_nntp_state_switch(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;

	/* Find the next group. */
	do {
		data->group++;

		if (data->group == ARRAY_LENGTH(&data->groups)) {
			io_writeline(data->io, "QUIT");
			fctx->state = fetch_nntp_state_quit;
			return (FETCH_BLOCK);
		}
	} while (ARRAY_ITEM(&data->groups, data->group)->ignore);

	fctx->state = fetch_nntp_state_group;
	return (FETCH_AGAIN);
}

/* Group state. */
int
fetch_nntp_state_group(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;

	group = ARRAY_ITEM(&data->groups, data->group);

	log_debug("%s: fetching group: %s", a->name, group->name);

	io_writeline(data->io, "GROUP %s", group->name);
	fctx->state = fetch_nntp_state_stat;
	return (FETCH_BLOCK);
}

/* Reset state. */
int
fetch_nntp_state_reset(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;

	group = ARRAY_ITEM(&data->groups, data->group);

	log_warnx("%s: last message not found. resetting group", a->name);

	if (group->id != NULL) {
		xfree(group->id);
		group->id = NULL;
	}
	group->last = 0;

	fctx->state = fetch_nntp_state_group;
	return (FETCH_AGAIN);
}

/* Stat state. */
int
fetch_nntp_state_stat(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	char			*line;
	u_int			 n;

	group = ARRAY_ITEM(&data->groups, data->group);

	if (fetch_nntp_check(a, fctx, &line, NULL, 1, 211) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	if (sscanf(line, "211 %u %*u %u", &group->size, &n) != 2)
		return (fetch_nntp_invalid(a, line));
	if (group->last > n) {
		log_warnx("%s: "
		    "new last %u is less than old %u", a->name, n, group->last);
		fctx->state = fetch_nntp_state_reset;
		return (FETCH_AGAIN);
	}
	group->size = n - group->last;

	if (group->last != 0) {
		io_writeline(data->io, "STAT %u", group->last);
		fctx->state = fetch_nntp_state_wait;
		return (FETCH_BLOCK);
	} else {
		io_writeline(data->io, "NEXT");
		fctx->state = fetch_nntp_state_next;
		return (FETCH_BLOCK);
	}
}

/* Wait state. Wait for and check STAT response. */
int
fetch_nntp_state_wait(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	char			*line, *id;
	u_int			 n;

	group = ARRAY_ITEM(&data->groups, data->group);

	if (fetch_nntp_check(a, fctx, &line, NULL, 1, 223) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	if (fetch_nntp_parse223(line, &n, &id) != 0)
		return (fetch_nntp_invalid(a, line));
	if (n != group->last) {
		log_warnx("%s: unexpected message number", a->name);
		xfree(id);
		return (FETCH_ERROR);
	}
	if (strcmp(id, group->id) != 0) {
		xfree(id);
		fctx->state = fetch_nntp_state_reset;
		return (FETCH_AGAIN);
	}
	log_debug2("%s: last message found: %u %s", a->name, group->last, id);
	xfree(id);

	io_writeline(data->io, "NEXT");
	fctx->state = fetch_nntp_state_next;
	return (FETCH_BLOCK);
}

/* Next state. Now we are fetching mail. */
int
fetch_nntp_state_next(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	char			*line, *id;
	u_int			 n;
	int			 code;

	group = ARRAY_ITEM(&data->groups, data->group);

	if (fetch_nntp_check(a, fctx, &line, &code, 2, 223, 421) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	if (code == 421) {
		/* Finished this group. Switch to the next. */
		fctx->state = fetch_nntp_state_switch;
		return (FETCH_AGAIN);
	}

	/* 223 code. Save this as last article. */
	if (fetch_nntp_parse223(line, &n, &id) != 0)
		return (fetch_nntp_invalid(a, line));
	if (n < group->last) {
		log_warnx("%s: message number out of order", a->name);
		return (FETCH_ERROR);
	}
	group->last = n;
	if (group->id != NULL)
		xfree(group->id);
	group->id = id;

	io_writeline(data->io, "ARTICLE");
	fctx->state = fetch_nntp_state_article;
	return (FETCH_BLOCK);
}

/* Article state. */
int
fetch_nntp_state_article(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	struct mail		*m = fctx->mail;
	char			*line;
	int			 code;

	group = ARRAY_ITEM(&data->groups, data->group);

	if (fetch_nntp_check(a, fctx, &line, &code, 2, 220, 423, 430) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	if (code == 423 || code == 430)
		return (FETCH_AGAIN);

	/* Open the mail. */
	if (mail_open(m, IO_BLOCKSIZE) != 0) {
		log_warn("%s: failed to create mail", a->name);
		return (FETCH_ERROR);
	}
	m->size = 0;

	/* Tag mail. */
	default_tags(&m->tags, group->name);
	add_tag(&m->tags, "group", "%s", group->name);
	add_tag(&m->tags, "server", "%s", data->server.host);
	add_tag(&m->tags, "port", "%s", data->server.port);

	data->flushing = 0;

	fctx->state = fetch_nntp_state_line;
	return (FETCH_AGAIN);
}

/* Line state. */
int
fetch_nntp_state_line(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_nntp_data	*data = a->data;
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

	io_writeline(data->io, "NEXT");
	fctx->state = fetch_nntp_state_next;
	return (FETCH_MAIL);
}

/* Quit state. */
int
fetch_nntp_state_quit(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (fetch_nntp_check(a, fctx, &line, NULL, 1, 205) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	fetch_nntp_save(a);

	fetch_nntp_abort(a);
	return (FETCH_EXIT);
}

void
fetch_nntp_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_nntp_data	*data = a->data;
	char			*names;

	names = fmt_strings("groups ", data->names);
	xsnprintf(buf, len, "nntp server \"%s\" port %s %s cache \"%s\"",
	    data->server.host, data->server.port, names, data->path);
	xfree(names);
}
