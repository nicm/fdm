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
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

int	 fetch_maildir_connect(struct account *);
int	 fetch_maildir_disconnect(struct account *);
int	 fetch_maildir_poll(struct account *, u_int *);
int	 fetch_maildir_fetch(struct account *, struct mail *);
int	 fetch_maildir_delete(struct account *);
void	 fetch_maildir_desc(struct account *, char *, size_t);

int	 maildir_makepaths(struct account *);
void	 maildir_freepaths(struct account *);

struct fetch fetch_maildir = {
	{ NULL, NULL },
	NULL,
	fetch_maildir_connect,
	fetch_maildir_poll,
	fetch_maildir_fetch,
	NULL,
	fetch_maildir_delete,
	NULL,
	fetch_maildir_disconnect,
	NULL,
	fetch_maildir_desc
};

/* Make an array of all the paths to visit. */
int
maildir_makepaths(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;
	char				*s, *path;
	u_int				 i, j;
	glob_t				 g;
	struct stat			 sb;
	struct strb			*tags;

	strb_create(&tags);
	default_tags(&tags, NULL, a);

	data->paths = xmalloc(sizeof *data->paths);
	ARRAY_INIT(data->paths);

	for (i = 0; i < ARRAY_LENGTH(data->maildirs); i++) {
		path = ARRAY_ITEM(data->maildirs, i, char *);
		s = replace(path, tags, NULL, 0, NULL);
		if (s == NULL || *s == '\0') {
			log_warnx("%s: empty path", a->name);
			goto error;
		}
		if (glob(s, GLOB_BRACE|GLOB_NOCHECK, NULL, &g) != 0) {
			log_warn("%s: glob(\"%s\")", a->name, s);
			goto error;
		}

		if (g.gl_pathc < 1)
			fatalx("negative or zero number of paths");
		for (j = 0; j < (u_int) g.gl_pathc; j++) {
			xasprintf(&path, "%s/cur", g.gl_pathv[j]);
			ARRAY_ADD(data->paths, path, char *);
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
			ARRAY_ADD(data->paths, path, char *);
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

		xfree(s);
	}

	strb_destroy(&tags);
	return (0);

error:
	if (s != NULL)
		xfree(s);
	maildir_freepaths(a);

	strb_destroy(&tags);
	return (1);
}

/* Free the array. */
void
maildir_freepaths(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;
	u_int			 	 i;

	for (i = 0; i < ARRAY_LENGTH(data->paths); i++)
		xfree(ARRAY_ITEM(data->paths, i, char *));

	ARRAY_FREEALL(data->paths);
}

int
fetch_maildir_connect(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;

	data->dirp = NULL;

	data->path = NULL;

	if (maildir_makepaths(a) != 0)
		return (1);
	data->index = 0;

	return (0);
}

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
		path = ARRAY_ITEM(data->paths, i, char *);

		log_debug("%s: trying path: %s", a->name, path);
		if ((dirp = opendir(path)) == NULL) {
			log_warn("%s: %s: opendir", a->name, path);
			return (POLL_ERROR);
		}

		while ((dp = readdir(dirp)) != NULL) {
			if (printpath(entry, sizeof entry, "%s/%s", path,
			    dp->d_name) != 0) {
				log_warn("%s: %s: printpath", a->name, path);
				closedir(dirp);
				return (POLL_ERROR);
			}
			if (stat(entry, &sb) != 0) {
				log_warn("%s: %s: stat", a->name, entry);
				closedir(dirp);
				return (POLL_ERROR);
			}

			if (!S_ISREG(sb.st_mode))
				continue;

			(*n)++;
		}

		closedir(dirp);
	}

	return (POLL_SUCCESS);
}

int
fetch_maildir_fetch(struct account *a, struct mail *m)
{
	struct fetch_maildir_data	*data = a->data;
	struct dirent			*dp;
	char	       			*ptr, path[MAXPATHLEN];
	struct stat			 sb;
	int				 fd;

restart:
	if (data->dirp == NULL) {
		data->path = ARRAY_ITEM(data->paths, data->index, char *);

		/* make the maildir name for the tag */
		/* XXX this sucks a bit, too much copying */
		strlcpy(path, data->path, sizeof path);
		strlcpy(data->maildir,
		    basename(dirname(path)), sizeof data->maildir);

		log_debug("%s: trying path: %s", a->name, data->path);
		if ((data->dirp = opendir(data->path)) == NULL) {
			log_warn("%s: %s: opendir", a->name, data->path);
			return (FETCH_ERROR);
		}
	}

	do {
		dp = readdir(data->dirp);
		if (dp == NULL) {
			closedir(data->dirp);
			data->dirp = NULL;

			data->index++;
			if (data->index == ARRAY_LENGTH(data->paths))
				return (FETCH_COMPLETE);
			goto restart;
		}

		if (printpath(data->entry, sizeof data->entry, "%s/%s",
		    data->path, dp->d_name) != 0) {
			log_warn("%s: %s: printpath", a->name, data->path);
			return (FETCH_ERROR);
		}
		if (stat(data->entry, &sb) != 0) {
			log_warn("%s: %s: stat", a->name, data->entry);
			return (FETCH_ERROR);
		}
	} while (!S_ISREG(sb.st_mode));

	log_debug2("%s: reading mail from: %s", a->name, data->entry);
	if (sb.st_size <= 0) {
		log_warnx("%s: %s: empty file", a->name, data->entry);
		return (FETCH_ERROR);
	}
	if ((uintmax_t) sb.st_size > SIZE_MAX)
		return (FETCH_OVERSIZE);
	if ((uintmax_t) sb.st_size > conf.max_size)
		return (FETCH_OVERSIZE);

	if ((fd = open(data->entry, O_RDONLY, 0)) < 0) {
		log_warn("%s: %s: open", a->name, data->entry);
		return (FETCH_ERROR);
	}

	mail_open(m, IO_ROUND(sb.st_size));
	default_tags(&m->tags, data->maildir, a);
	add_tag(&m->tags, "maildir", "%s", data->maildir);
	
	log_debug2("%s: reading %ju bytes", a->name, (uintmax_t) sb.st_size);
	if (read(fd, m->data, sb.st_size) != sb.st_size) {
		close(fd);
		log_warn("%s: %s: read", a->name, data->entry);
		return (FETCH_ERROR);
	}
	close(fd);

	/* find the body */
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
	m->size = sb.st_size;

	return (FETCH_SUCCESS);
}

int
fetch_maildir_delete(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;

	if (unlink(data->entry) != 0) {
		log_warn("%s: %s: unlink", a->name, data->entry);
		return (1);
	}

	return (0);
}

int
fetch_maildir_disconnect(struct account *a)
{
	struct fetch_maildir_data	*data = a->data;

	maildir_freepaths(a);

	if (data->dirp != NULL)
		closedir(data->dirp);

	return (0);
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
