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

int	fetch_nntp_start(struct account *, int *);
void	fetch_nntp_fill(struct account *, struct io **, u_int *);
int	fetch_nntp_finish(struct account *, int);
int	fetch_nntp_poll(struct account *, u_int *);
int	fetch_nntp_fetch(struct account *, struct mail *);
void	fetch_nntp_desc(struct account *, char *, size_t);

int	fetch_nntp_code(char *);
char   *fetch_nntp_line(struct account *, char **, size_t *);
char   *fetch_nntp_check(struct account *, char **, size_t *, int *, u_int,
	    ...);
int	fetch_nntp_group(struct account *, char **, size_t *);
int	fetch_nntp_parse223(char *, u_int *, char **);

int	fetch_nntp_load(struct account *);
int	fetch_nntp_save(struct account *);

#define GET_GROUP(d, i) ARRAY_ITEM(&d->groups, i, struct fetch_nntp_group *)
#define CURRENT_GROUP(d) GET_GROUP(d, d->group)
#define TOTAL_GROUPS(d) ARRAY_LENGTH(&d->groups)
#define ADD_GROUP(d, g) ARRAY_ADD(&d->groups, g, struct fetch_nntp_group *)

struct fetch fetch_nntp = {
	"nntp",
	{ "nntp", NULL },
	fetch_nntp_start,
	fetch_nntp_fill,
	fetch_nntp_poll,
	fetch_nntp_fetch,
	fetch_nntp_save,
	NULL,
	fetch_nntp_finish,
	fetch_nntp_desc
};

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

char *
fetch_nntp_line(struct account *a, char **lbuf, size_t *llen)
{
	struct fetch_nntp_data	*data = a->data;
	char			*line, *cause;

	switch (io_pollline2(data->io, &line, lbuf, llen, &cause)) {
	case 0:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (NULL);
	case -1:
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (NULL);
	}

	return (line);
}

char *
fetch_nntp_check(struct account *a, char **lbuf, size_t *llen, int *cdp,
    u_int n, ...)
{
	va_list	 ap;
	u_int	 i;
	int	 code, arg;
	char	*line;

	if (cdp == NULL)
		cdp = &code;

	do {
		if ((line = fetch_nntp_line(a, lbuf, llen)) == NULL)
			return (NULL);

		*cdp = fetch_nntp_code(line);
		if (*cdp == -1)
			goto error;
	} while (*cdp >= 100 && *cdp <= 199);

	va_start(ap, n);
	for (i = n; i > 0; i--) {
		arg = va_arg(ap, int);
		if (*cdp == arg)
			break;
	}
	va_end(ap);
	if (i == 0)
		goto error;

	return (line);

error:
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (NULL);
}

int
fetch_nntp_parse223(char *line, u_int *n, char **id)
{
	char	*ptr, *ptr2;

	if (sscanf(line, "223 %u ", n) != 1)
		return (1);

	ptr = strchr(line, '<');
	if (ptr == NULL)
		return (1);
	ptr2 = strchr(ptr, '>');
	if (ptr2 == NULL)
		return (1);
	ptr++;

	*id = xmalloc(ptr2 - ptr + 1);
	memcpy(*id, ptr, ptr2 - ptr);
	(*id)[ptr2 - ptr] = '\0';

	return (0);
}

int
fetch_nntp_group(struct account *a, char **lbuf, size_t *llen)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	char			*line, *id;
	u_int			 n, last;

	group = CURRENT_GROUP(data);
	log_debug("%s: fetching group: %s", a->name, group->name);

	io_writeline(data->io, "GROUP %s", group->name);
	if ((line = fetch_nntp_check(a, lbuf, llen, NULL, 1, 211)) == NULL)
		return (1);
	if (sscanf(line, "211 %u %*u %u", &group->size, &last) != 2) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (1);
	}

	if (group->last > last) {
		log_warnx("%s: new last %u is less than old %u", a->name,
		    last, group->last);
		goto invalid;
	}
	group->size = last - group->last;

	io_writeline(data->io, "STAT %u", group->last);
	if ((line = fetch_nntp_check(a, lbuf, llen, NULL, 1, 223)) == NULL)
		return (1);

	if (fetch_nntp_parse223(line, &n, &id) != 0)
		goto invalid;
	if (n != group->last) {
		log_warnx("%s: unexpected message number", a->name);
		xfree(id);
		return (1);
	}
	if (strcmp(id, group->id) != 0) {
		xfree(id);
		goto invalid;
	}
	log_debug2("%s: last message found: %u %s", a->name, group->last, id);
	xfree(id);

	return (0);

invalid:
	log_warnx("%s: last message not found. resetting group", a->name);

	io_writeline(data->io, "GROUP %s", group->name);
	if ((line = fetch_nntp_check(a, lbuf, llen, NULL, 1, 211)) == NULL)
		return (1);
	if (sscanf(line, "211 %u %*u %*u", &group->size) != 1) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (1);
	}

	if (group->id != NULL) {
		xfree(group->id);
		group->id = NULL;
	}
	group->last = 0;

	return (0);
}

int
fetch_nntp_load(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	int			 fd = -1, fd2;
	FILE			*f = NULL;
	char			*name, *id;
	size_t			 namelen, idlen;
	u_int			 last, i;

	if ((fd = openlock(data->path, conf.lock_types, O_RDONLY, 0)) == -1) {
		log_warn("%s: %s", a->name, data->path);
		goto error;
	}

	if ((fd2 = dup(fd)) == -1) {
		log_warn("%s: dup", a->name);
		goto error;
	}
	if ((f = fdopen(fd2, "r")) == NULL) {
		log_warn("%s: fdopen", a->name);
		goto error;
	}

	for (;;) {
		if (fscanf(f, "%zu ", &namelen) != 1) {
			/* EOF is allowed only at the start of a line */
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

		/* got a group. fill it in */
		group = NULL;
		for (i = 0; i < TOTAL_GROUPS(data); i++) {
			group = GET_GROUP(data, i);
			if (strcmp(group->name, name) == 0)
				break;
		}
		if (i == TOTAL_GROUPS(data)) {
			/*
			 * Not found. add it so it is saved when the file is
			 * resaved, but with ignore set so it isn't fetched.
			 */
			group = xcalloc(1, sizeof *group);
			ADD_GROUP(data, group);
			group->ignore = 1;
			group->name = xstrdup(name);
		}
		log_debug2("%s: found group in cache: %s", a->name, name);

		group->last = last;
		group->id = id;
		xfree(name);
	}

	if (fclose(f) != 0) {
		log_warn("%s: fclose", a->name);
		f = NULL;
		goto error;
	}

	closelock(fd, data->path, conf.lock_types);
	return (0);

invalid:
	log_warnx("%s: invalid cache entry", a->name);

error:
	if (f != NULL)
		fclose(f);
	if (fd != -1)
		closelock(fd, data->path, conf.lock_types);

	return (1);
}

int
fetch_nntp_save(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	char			 tmp[MAXPATHLEN];
	int			 fd = -1;
	FILE			*f = NULL;
	u_int			 i;

	if (printpath(tmp, sizeof tmp, "%s.XXXXXXXXXX", data->path) != 0) {
		log_warn("%s: %s: printpath", a->name, data->path);
		goto error;
	}
	if ((fd = mkstemp(tmp)) == -1) {
		log_warn("%s: %s: mkstemp", a->name, tmp);
		goto error;
	}
	cleanup_register(tmp);

	if ((f = fdopen(fd, "r+")) == NULL) {
		log_warn("%s: fdopen", a->name);
		goto error;
	}
	fd = -1;

	for (i = 0; i < TOTAL_GROUPS(data); i++) {
		group = GET_GROUP(data, i);
		if (group->id == NULL)
			continue;
		fprintf(f, "%zu %s %u %zu %s\n", strlen(group->name),
		    group->name, group->last, strlen(group->id), group->id);
	}

	if (fclose(f) != 0) {
		log_warn("%s: fclose", a->name);
		f = NULL;
		goto error;
	}
	f = NULL;

	if (rename(tmp, data->path) == -1) {
		log_warn("%s: rename", a->name);
		goto error;
	}

	cleanup_deregister(tmp);
	return (0);

error:
	if (f != NULL || fd != -1) {
		if (f != NULL)
			fclose(f);
		if (fd != -1)
			close(fd);
		if (unlink(tmp) != 0)
			fatal("unlink");
	}
	cleanup_deregister(tmp);
	return (1);
}

int
fetch_nntp_start(struct account *a, unused int *total)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	u_int			 i;
	char			*line, *cause;

	data->llen = IO_LINESIZE;
	data->lbuf = xmalloc(data->llen);

	ARRAY_INIT(&data->groups);
	for (i = 0; i < ARRAY_LENGTH(data->names); i++) {
		group = xmalloc(sizeof *group);
		group->name = xstrdup(ARRAY_ITEM(data->names, i, char *));
		group->id = NULL;
		group->ignore = 0;
		ADD_GROUP(data, group);
	}

	data->group = 0;
	data->state = NNTP_START;

	if (fetch_nntp_load(a) != 0)
		return (FETCH_ERROR);

	data->io = connectproxy(&data->server,
	    conf.proxy ,IO_CRLF, conf.timeout, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	data->group = 0;
	if (CURRENT_GROUP(data)->ignore) {
		do {
			data->group++;
			if (data->group == TOTAL_GROUPS(data)) {
				log_debug2("%s: no groups found", a->name);
				return (FETCH_ERROR);
			}
		} while (CURRENT_GROUP(data)->ignore);
	}

	line = fetch_nntp_check(a, &data->lbuf, &data->llen, NULL, 1, 200);
	if (line == NULL)
		return (FETCH_ERROR);

	if (fetch_nntp_group(a, &data->lbuf, &data->llen) != 0)
		return (FETCH_ERROR);

	return (FETCH_SUCCESS);
}

void
fetch_nntp_fill(struct account *a, struct io **iop, u_int *n)
{
	struct fetch_nntp_data	*data = a->data;

	iop[(*n)++] = data->io;
}

int
fetch_nntp_finish(struct account *a, int aborted)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	u_int			 i;

	if (!aborted)
		fetch_nntp_save(a);

	for (i = 0; i < TOTAL_GROUPS(data); i++) {
		group = GET_GROUP(data, i);
		xfree(group->name);
		if (group->id != NULL)
			xfree(group->id);
		xfree(group);
	}
	ARRAY_FREE(&data->groups);

	if (data->io == NULL) {
		xfree(data->lbuf);
		return (FETCH_SUCCESS);
	}

	io_writeline(data->io, "QUIT");
	if (!aborted &&
	    fetch_nntp_check(a, &data->lbuf, &data->llen, NULL, 1, 205) == NULL)
		goto error;

	io_close(data->io);
	io_free(data->io);

	xfree(data->lbuf);
	return (FETCH_SUCCESS);

error:
	io_close(data->io);
	io_free(data->io);

	xfree(data->lbuf);
	return (FETCH_ERROR);
}

int
fetch_nntp_poll(struct account *a, u_int *n)
{
	struct fetch_nntp_data	*data = a->data;

	*n = CURRENT_GROUP(data)->size;
	for (;;) {
		data->group++;
		if (data->group == TOTAL_GROUPS(data))
			break;
		if (CURRENT_GROUP(data)->ignore)
			continue;

		if (fetch_nntp_group(a, &data->lbuf, &data->llen) != 0)
			return (FETCH_ERROR);
		(*n) += CURRENT_GROUP(data)->size;
	}

	return (FETCH_SUCCESS);
}

int
fetch_nntp_fetch(struct account *a, struct mail *m)
{
	struct fetch_nntp_data 	*data = a->data;
	struct fetch_nntp_group	*group;
	char			*line, *id;
	int			 code;
	u_int			 n;
	size_t			 len;

restart:
	line = NULL;
	code = 0;
	if (data->state != NNTP_START) {
		line = io_readline2(data->io, &data->lbuf, &data->llen);
		if (line == NULL)
			return (FETCH_AGAIN);
		if (data->state != NNTP_LINE) {
			code = fetch_nntp_code(line);
			if (code >= 100 && code <= 199)
				goto restart;
		}
	}

	switch (data->state) {
	case NNTP_START:
		io_writeline(data->io, "NEXT");
		data->state = NNTP_NEXT;
		break;
	case NNTP_NEXT:
		if (code != 223 && code != 421)
			goto bad;
		if (code == 421) {
			do {
				data->group++;
				if (data->group == TOTAL_GROUPS(data))
					return (FETCH_COMPLETE);
			} while (CURRENT_GROUP(data)->ignore);
			if (fetch_nntp_group(a, &data->lbuf, &data->llen) != 0)
				return (FETCH_ERROR);
			io_writeline(data->io, "NEXT");
			goto restart;
		}
		/* fill this in as the last article */
		if (fetch_nntp_parse223(line, &n, &id) != 0) {
			log_warnx("%s: malformed response: %s", a->name, line);
			goto restart;
		}
		group = CURRENT_GROUP(data);
		if (n < group->last) {
			log_warnx("%s: message number out of order", a->name);
			return (FETCH_ERROR);
		}
		group->last = n;
		if (group->id != NULL)
			xfree(group->id);
		group->id = id;

		io_writeline(data->io, "ARTICLE");
		data->state = NNTP_ARTICLE;
		break;
	case NNTP_ARTICLE:
		if (code == 423 || code == 430)
			goto restart;
		if (code != 220)
			goto bad;

		if (mail_open(m, IO_BLOCKSIZE) != 0) {
			log_warn("%s: failed to create mail", a->name);
			return (FETCH_ERROR);
		}

		m->size = 0;

		m->auxdata = NULL;
		m->auxfree = NULL;

		default_tags(&m->tags, CURRENT_GROUP(data)->name, a);
		add_tag(&m->tags, "group", "%s", CURRENT_GROUP(data)->name);
		add_tag(&m->tags, "server", "%s", data->server.host);
		add_tag(&m->tags, "port", "%s", data->server.port);

		data->flushing = 0;
		data->lines = 0;
		data->bodylines = -1;

		data->state = NNTP_LINE;
		break;
	case NNTP_LINE:
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
		break;
	}

	goto restart;

complete:
	data->state = NNTP_START;

	add_tag(&m->tags, "lines", "%u", data->lines);
	if (data->bodylines == -1) {
		add_tag(&m->tags, "body_lines", "0");
		add_tag(&m->tags, "header_lines", "%u", data->lines - 1);
	} else {
		add_tag(&m->tags, "body_lines", "%d", data->bodylines - 1);
		add_tag(&m->tags, "header_lines", "%d", data->lines -
		    data->bodylines);
	}

	if (data->flushing)
		return (FETCH_OVERSIZE);

	return (FETCH_SUCCESS);

bad:
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (FETCH_ERROR);
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
