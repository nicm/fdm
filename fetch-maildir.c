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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

int	fetch_maildir_connect(struct account *);
int	fetch_maildir_completed(struct account *);
int	fetch_maildir_fetch(struct account *, struct fetch_ctx *);
int	fetch_maildir_poll(struct account *, u_int *);
int	fetch_maildir_disconnect(struct account *, int);
void	fetch_maildir_desc(struct account *, char *, size_t);

void	fetch_maildir_free(void *);

int	fetch_maildir_makepaths(struct account *);
void	fetch_maildir_freepaths(struct account *);

int	fetch_maildir_next(struct account *, struct fetch_ctx *);
int	fetch_maildir_open(struct account *, struct fetch_ctx *);
int	fetch_maildir_mail(struct account *, struct fetch_ctx *);

struct fetch fetch_maildir = {
	"maildir",
	fetch_maildir_connect,
	NULL,
	NULL,
	fetch_maildir_completed,
	NULL,
	fetch_maildir_fetch,
	fetch_maildir_poll,
	NULL,
	NULL,
	fetch_maildir_disconnect,
	fetch_maildir_desc
};

void
fetch_maildir_free(void *ptr)
{
	struct fetch_maildir_mail	*aux = ptr;

	xfree(aux);
}

/* Make an array of all the paths to visit. */
int
fetch_maildir_makepaths(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;
	char				*path;
	u_int				 i, j;
	glob_t				 g;
	struct stat			 sb;

	data->paths = xmalloc(sizeof *data->paths);
	ARRAY_INIT(data->paths);

	for (i = 0; i < ARRAY_LENGTH(data->maildirs); i++) {
		path = ARRAY_ITEM(data->maildirs, i);
		if (glob(path, GLOB_BRACE|GLOB_NOCHECK, NULL, &g) != 0) {
			log_warn("%s: glob(\"%s\")", a->name, path);
			goto error;
		}

		if (g.gl_pathc < 1)
			fatalx("negative or zero number of paths");
		for (j = 0; j < (u_int) g.gl_pathc; j++) {
			xasprintf(&path, "%s/cur", g.gl_pathv[j]);
			ARRAY_ADD(data->paths, path);
			if (stat(path, &sb) != 0) {
				log_warn("%s: %s", a->name, path);
				goto error;
			}
			if (!S_ISDIR(sb.st_mode)) {
				errno = ENOTDIR;
				log_warn("%s: %s", a->name, path);
				goto error;
			}

			xasprintf(&path, "%s/new", g.gl_pathv[j]);
			ARRAY_ADD(data->paths, path);
			if (stat(path, &sb) != 0) {
				log_warn("%s", path);
				goto error;
			}
			if (!S_ISDIR(sb.st_mode)) {
				errno = ENOTDIR;
				log_warn("%s", path);
				goto error;
			}
		}
	}

	return (0);

error:
	fetch_maildir_freepaths(a);
	return (-1);
}

/* Free the array. */
void
fetch_maildir_freepaths(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;
	u_int			 	 i;

	for (i = 0; i < ARRAY_LENGTH(data->paths); i++)
		xfree(ARRAY_ITEM(data->paths, i));

	ARRAY_FREEALL(data->paths);
}

/* Build path list and set initial state. */
int
fetch_maildir_connect(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;

	if (fetch_maildir_makepaths(a) != 0)
		return (-1);
	data->index = 0;

	if (ARRAY_EMPTY(data->paths)) {
		log_warnx("%s: no maildirs found", a->name);
		return (-1);
	}

	data->state = fetch_maildir_open;
	return (0);
}

/* Check if all paths completed. */
int
fetch_maildir_completed(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;

	return (data->index >= ARRAY_LENGTH(data->paths));
}

/* Clean up and free data. */
int
fetch_maildir_disconnect(struct account *a, unused int aborted)
{
	struct fetch_maildir_data	*data = a->data;

	fetch_maildir_freepaths(a);

	if (data->dirp != NULL && closedir(data->dirp) != 0) {
		log_warn("%s: %s: closedir", a->name, data->path);
		return (-1);
	}

	return (0);
}

/* Fetch mail. */
int
fetch_maildir_fetch(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_maildir_data	*data = a->data;

	return (data->state(a, fctx));
}

/* Poll for maildir total. */
int
fetch_maildir_poll(struct account *a, u_int *n)
{
	struct fetch_maildir_data	*data = a->data;
	u_int				 i;
	char				*path, entry[MAXPATHLEN];
	DIR				*dirp;
	struct dirent			*dp;
	struct stat			 sb;

	*n = 0;
	for (i = 0; i < ARRAY_LENGTH(data->paths); i++) {
		path = ARRAY_ITEM(data->paths, i);

		log_debug("%s: trying path: %s", a->name, path);
		if ((dirp = opendir(path)) == NULL) {
			log_warn("%s: %s: opendir", a->name, path);
			return (-1);
		}

		while ((dp = readdir(dirp)) != NULL) {
			if (dp->d_type == DT_REG) {
				(*n)++;
				continue;
			}
			if (dp->d_type != DT_UNKNOWN)
				continue;

			if (printpath(entry, sizeof entry, "%s/%s", path,
			    dp->d_name) != 0) {
				log_warn("%s: %s: printpath", a->name, path);
				closedir(dirp);
				return (-1);
			}

			if (stat(entry, &sb) != 0) {
				log_warn("%s: %s: stat", a->name, entry);
				closedir(dirp);
				return (-1);
			}
			if (!S_ISREG(sb.st_mode))
				continue;

			(*n)++;
		}

		if (closedir(dirp) != 0) {
			log_warn("%s: %s: closedir", a->name, path);
			return (-1);
		}
	}

	return (0);
}

/* Next state. Move to next path. */
int
fetch_maildir_next(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_maildir_data	*data = a->data;
	struct fetch_maildir_mail	*aux;
	struct mail			*m;

	/* Delete mail if any. */
	while ((m = done_mail(a, fctx)) != NULL) {
		aux = m->auxdata;
		if (m->decision == DECISION_DROP && unlink(aux->path) != 0) {
			log_warn("%s: %s: unlink", a->name, aux->path);
			return (FETCH_ERROR);
		}
		dequeue_mail(a, fctx);
	}

	if (!fetch_maildir_completed(a))
		data->index++;
	if (fetch_maildir_completed(a))
		return (FETCH_HOLD);

	data->state = fetch_maildir_open;
	return (FETCH_AGAIN);
}

/* Open state. */
int
fetch_maildir_open(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_maildir_data	*data = a->data;

	data->path = ARRAY_ITEM(data->paths, data->index);

	/* Open the directory. */
	log_debug2("%s: trying path: %s", a->name, data->path);
	if ((data->dirp = opendir(data->path)) == NULL) {
		log_warn("%s: %s: opendir", a->name, data->path);
		return (FETCH_ERROR);
	}

	data->state = fetch_maildir_mail;
	return (FETCH_AGAIN);
}

/* Mail state. Find and read mail file. */
int
fetch_maildir_mail(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_maildir_data	*data = a->data;
	struct fetch_maildir_mail	*aux;
	struct mail			*m;
	struct dirent			*dp;
	char	       			*ptr, *maildir, name[MAXPATHLEN];
	struct stat			 sb;
	uintmax_t			 size;
	int				 fd;
	ssize_t				 n;

	/* Delete mail if any. */
	while ((m = done_mail(a, fctx)) != NULL) {
		aux = m->auxdata;
		if (m->decision == DECISION_DROP && unlink(aux->path) != 0) {
			log_warn("%s: %s: unlink", a->name, aux->path);
			return (FETCH_ERROR);
		}
		dequeue_mail(a, fctx);
	}

restart:
	/* Read the next dir entry. */
	dp = readdir(data->dirp);
	if (dp == NULL) {
		if (closedir(data->dirp) != 0) {
			log_warn("%s: %s: closedir", a->name, data->path);
			return (FETCH_ERROR);
		}
		data->dirp = NULL;

		data->state = fetch_maildir_next;
		return (FETCH_AGAIN);
	}

	if (printpath(name,
	    sizeof name, "%s/%s", data->path, dp->d_name) != 0) {
		log_warn("%s: %s: printpath", a->name, data->path);
		return (FETCH_ERROR);
	}
	if (stat(name, &sb) != 0) {
		log_warn("%s: %s: stat", a->name, name);
		return (FETCH_ERROR);
	}
	if (!S_ISREG(sb.st_mode))
		goto restart;

	/* Create a new mail. */
	m = xcalloc(1, sizeof *m);
	m->shm.fd = -1;

	/* Got a valid entry, start reading it. */
	log_debug2("%s: reading mail from: %s", a->name, name);
	if (sb.st_size <= 0) {
		if (empty_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		mail_destroy(m);
		return (FETCH_AGAIN);
	}
	size = sb.st_size;
	if (size > SIZE_MAX || size > conf.max_size) {
		if (oversize_mail(a, fctx, m) != 0)
			return (FETCH_ERROR);
		mail_destroy(m);
		return (FETCH_AGAIN);
	}

	/* Open the mail. */
	if (mail_open(m, IO_ROUND(sb.st_size)) != 0) {
		log_warn("%s: failed to create mail", a->name);
		mail_destroy(m);
		return (FETCH_ERROR);
	}
	m->size = 0;

	/* Open the file. */
	if ((fd = open(name, O_RDONLY, 0)) == -1) {
		log_warn("%s: %s: open", a->name, name);
		mail_destroy(m);
		return (FETCH_ERROR);
	}

	/* Add the tags. */
	maildir = xbasename(xdirname(data->path));
	default_tags(&m->tags, maildir, a);
	add_tag(&m->tags, "maildir", "%s", maildir);

	/* Add aux data. */
	aux = xmalloc(sizeof *aux);
	strlcpy(aux->path, name, sizeof aux->path);
	m->auxdata = aux;
	m->auxfree = fetch_maildir_free;

	/* Read the mail. */
	if ((n = read(fd, m->data, size)) == -1 || (size_t) n != size) {
		close(fd);
		log_warn("%s: %s: read", a->name, name);
		mail_destroy(m);
		return (FETCH_ERROR);
	}
	close(fd);
	log_debug2("%s: read %ju bytes", a->name, size);
	m->size = size;

	/* Find the body. */
	m->body = -1;
	ptr = m->data;
	while ((ptr = memchr(ptr, '\n', (m->data + m->size) - ptr)) != NULL) {
		ptr++;
		if (ptr < (m->data + m->size) && *ptr == '\n') {
			ptr++;
			if (ptr != (m->data + m->size))
				m->body = ptr - m->data;
			break;
		}
	}

	/* And queue the mail. */
	enqueue_mail(a, fctx, m);

	return (FETCH_AGAIN);
}

void
fetch_maildir_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_maildir_data	*data = a->data;
	char				*maildirs;

	maildirs = fmt_strings("maildirs ", data->maildirs);
	strlcpy(buf, maildirs, len);
	xfree(maildirs);
}
