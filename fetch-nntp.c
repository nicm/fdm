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

int	fetch_nntp_init(struct account *);
int	fetch_nntp_free(struct account *);
int	fetch_nntp_connect(struct account *);
int	fetch_nntp_disconnect(struct account *);
int	fetch_nntp_poll(struct account *, u_int *);
int	fetch_nntp_fetch(struct account *, struct mail *);
int	fetch_nntp_delete(struct account *);
int	fetch_nntp_keep(struct account *);
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
	{ "nntp", NULL },
	fetch_nntp_init,
	fetch_nntp_connect,
	fetch_nntp_poll,
	fetch_nntp_fetch,
	fetch_nntp_save,
	NULL,
	NULL,
	fetch_nntp_disconnect,
	fetch_nntp_free,
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
	char	*line;
	va_list	 ap;
	u_int	 i;
	int	 code, arg;

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
	log_debug("%s: last message found: %u %s", a->name, group->last, id);
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
		log_debug("%s: found group in cache: %s", a->name, name);

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
		close(fd);
		unlink(tmp);
		goto error;
	}

	for (i = 0; i < TOTAL_GROUPS(data); i++) {
		group = GET_GROUP(data, i);
		if (group->id == NULL)
			continue;
		fprintf(f, "%zu %s %u %zu %s\n", strlen(group->name),
		    group->name, group->last, strlen(group->id), group->id);
	}

	fclose(f);

	if (rename(tmp, data->path) == -1) {
		log_warn("%s: rename", a->name);
		unlink(tmp);
		goto error;
	}

	cleanup_deregister(tmp);
	return (0);

error:
	cleanup_deregister(tmp);
	return (1);
}

int
fetch_nntp_init(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	u_int			 i;

	ARRAY_INIT(&data->groups);
	for (i = 0; i < ARRAY_LENGTH(data->names); i++) {
		group = xmalloc(sizeof *group);
		group->name = xstrdup(ARRAY_ITEM(data->names, i, char *));
		group->id = NULL;
		group->ignore = 0;
		ADD_GROUP(data, group);
	}

	data->group = 0;

	return (0);
}

int
fetch_nntp_free(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	struct fetch_nntp_group	*group;
	u_int			 i;

	for (i = 0; i < TOTAL_GROUPS(data); i++) {
		group = GET_GROUP(data, i);
		xfree(group->name);
		if (group->id != NULL)
			xfree(group->id);
		xfree(group);
	}
	ARRAY_FREE(&data->groups);

	return (0);
}

int
fetch_nntp_connect(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	char			*lbuf, *line, *cause;
	size_t			 llen;

	data->io = connectproxy(&data->server, conf.proxy, IO_CRLF,
	    conf.timeout * 1000, &cause);
	if (data->io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}
	if (conf.debug > 3 && !conf.syslog)
		data->io->dup_fd = STDOUT_FILENO;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	if (fetch_nntp_load(a) != 0)
		goto error;
	data->group = 0;
	if (CURRENT_GROUP(data)->ignore) {
		do {
			data->group++;
			if (data->group == TOTAL_GROUPS(data)) {
				log_debug("%s: no groups found", a->name);
				goto error;
			}
		} while (CURRENT_GROUP(data)->ignore);
	}

	if ((line = fetch_nntp_check(a, &lbuf, &llen, NULL, 1, 200)) == NULL)
		goto error;

	if (fetch_nntp_group(a, &lbuf, &llen) != 0)
		goto error;

	xfree(lbuf);
	return (0);

error:
	io_writeline(data->io, "QUIT");
	io_flush(data->io, NULL);

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (1);
}

int
fetch_nntp_disconnect(struct account *a)
{
	struct fetch_nntp_data	*data = a->data;
	char			*lbuf, *line;
	size_t			 llen;

	fetch_nntp_save(a);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	io_writeline(data->io, "QUIT");
	if ((line = fetch_nntp_check(a, &lbuf, &llen, NULL, 1, 205)) == NULL)
		goto error;

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (0);

error:
	io_writeline(data->io, "QUIT");
	io_flush(data->io, NULL);

	io_close(data->io);
	io_free(data->io);

	xfree(lbuf);
	return (1);
}

int
fetch_nntp_poll(struct account *a, u_int *n)
{
	struct fetch_nntp_data       	*data = a->data;
	char			*lbuf;
	size_t			 llen;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	*n = CURRENT_GROUP(data)->size;
	for (;;) {
		data->group++;
		if (data->group == TOTAL_GROUPS(data))
			break;
		if (CURRENT_GROUP(data)->ignore)
			continue;

		if (fetch_nntp_group(a, &lbuf, &llen) != 0)
			goto error;
		(*n) += CURRENT_GROUP(data)->size;
	}

	xfree(lbuf);
	return (0);

error:
	xfree(lbuf);
	return (1);
}

int
fetch_nntp_fetch(struct account *a, struct mail *m)
{
	struct fetch_nntp_data 	*data = a->data;
	struct fetch_nntp_group	*group;
	char			*lbuf, *line, *id;
	size_t			 llen, off, len;
	u_int			 lines, n;
	int			 code, flushing;

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

restart:
	io_writeline(data->io, "NEXT");
	line = fetch_nntp_check(a, &lbuf, &llen, &code, 2, 223, 421);
	if (line == NULL)
		goto error;
	if (code == 421) {
		do {
			data->group++;
			if (data->group == TOTAL_GROUPS(data)) {
				xfree(lbuf);
				return (FETCH_COMPLETE);
			}
		} while (CURRENT_GROUP(data)->ignore);
		if (fetch_nntp_group(a, &lbuf, &llen) != 0)
			goto error;
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
		goto error;
	}
	group->last = n;
	if (group->id != NULL)
		xfree(group->id);
	group->id = id;

	/* retrieve the article */
	io_writeline(data->io, "ARTICLE");
	line = fetch_nntp_check(a, &lbuf, &llen, &code, 3, 220, 423, 430);
	if (line == NULL)
		goto error;
	if (code == 423 || code == 430)
		goto restart;

	mail_open(m, IO_BLOCKSIZE);
	default_tags(&m->tags, CURRENT_GROUP(data)->name, a);
	add_tag(&m->tags, "group", "%s", CURRENT_GROUP(data)->name);
	add_tag(&m->tags, "server", "%s", data->server.host);
	add_tag(&m->tags, "port", "%s", data->server.port);

	flushing = 0;
	off = lines = 0;
	for (;;) {
		if ((line = fetch_nntp_line(a, &lbuf, &llen)) == NULL)
			goto error;

		if (line[0] == '.' && line[1] == '.')
			line++;
		else if (line[0] == '.') {
			m->size = off;
			break;
		}

		len = strlen(line);
		if (len == 0 && m->body == -1)
			m->body = off + 1;

		if (!flushing) {
			resize_mail(m, off + len + 1);

			if (len > 0)
				memcpy(m->data + off, line, len);
			m->data[off + len] = '\n';
		}

		lines++;
		off += len + 1;
		if (off + lines > conf.max_size)
			flushing = 1;
	}

	xfree(lbuf);
	if (flushing)
		return (FETCH_OVERSIZE);
	return (FETCH_SUCCESS);

error:
	xfree(lbuf);
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
