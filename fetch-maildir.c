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
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	 maildir_connect(struct account *);
int	 maildir_disconnect(struct account *);
int	 maildir_poll(struct account *, u_int *);
int	 maildir_fetch(struct account *, struct mail *);
int	 maildir_delete(struct account *);
char	*maildir_desc2(struct account *); /* conflicts with deliver-maildir.c */

struct fetch	fetch_maildir = { { NULL, NULL },
				  maildir_connect,
				  maildir_poll,
				  maildir_fetch,
				  maildir_delete,
				  NULL,
				  NULL,
				  maildir_disconnect,
				  maildir_desc2
};

int
maildir_connect(struct account *a)
{
	struct maildir_data	*data = a->data;

	data->index = 0;
	data->dirp = NULL;

	data->path = NULL;
	data->entry = NULL;

	return (0);
}

int
maildir_poll(struct account *a, u_int *n)
{
	struct maildir_data	*data = a->data;
	u_int			 i;
	char			*s, path[MAXPATHLEN], name[MAXPATHLEN];
	DIR			*dirp;
	struct dirent		*dp;
	struct stat		 sb;

	*n = 0;
	for (i = 0; i < ARRAY_LENGTH(data->paths); i++) {
		s = replaceinfo(ARRAY_ITEM(data->paths, i, char *), a, NULL,
		    NULL);
		if (s == NULL || *s == '\0') {
			log_warnx("%s: empty path", a->name);
			if (s != NULL)
				xfree(s);
			return (POLL_ERROR);
		}

		if (xsnprintf(path, sizeof path, "%s/cur", s) < 0) {
			log_warn("%s: %s: xsnprintf", a->name, s);
			xfree(s);
			return (POLL_ERROR);
		}			
		xfree(s);

		if ((dirp = opendir(path)) == NULL) {
			log_warn("%s: %s: opendir", a->name, path);
			return (POLL_ERROR);
		}

		while ((dp = readdir(dirp)) != NULL) {
			if (xsnprintf(name, sizeof name, "%s/%s", path,
			    dp->d_name) < 0) {
				log_warn("%s: %s/%s: xsnprintf", a->name, 
				    path, dp->d_name);
				closedir(dirp);
				return (POLL_ERROR);
			}
			if (stat(name, &sb) != 0) {
				log_warn("%s: %s: stat", a->name, name);
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
maildir_fetch(struct account *a, struct mail *m)
{
	struct maildir_data	*data = a->data;
	char			*s, *ptr, *end;
	struct dirent		*dp;
	struct stat		 sb;
	int			 fd;

restart:	
	if (data->dirp == NULL) {
		s = ARRAY_ITEM(data->paths, data->index, char *);
		data->path = replaceinfo(s, a, NULL, NULL);
		if (data->path == NULL || *data->path == '\0') {
			log_warnx("%s: empty path", a->name);
			return (FETCH_ERROR);
		}
		log_debug("%s: opening maildir: %s", a->name, data->path);

		xasprintf(&s, "%s/cur", data->path);
		if ((data->dirp = opendir(s)) == NULL) {
			log_warn("%s: %s: opendir", a->name, data->path);
			return (FETCH_ERROR);
		}
	}

	do {
		dp = readdir(data->dirp);
		if (dp == NULL) {
			closedir(data->dirp);
			data->dirp = NULL;	
			xfree(data->path);
			data->path = NULL;
			
			data->index++;
			if (data->index == ARRAY_LENGTH(data->paths))
				return (FETCH_COMPLETE);
			goto restart;
		}

		if (data->entry != NULL)
			xfree(data->entry);
		xasprintf(&data->entry, "%s/cur/%s", data->path, dp->d_name);
		if (stat(data->entry, &sb) != 0) {
			log_warn("%s: %s: stat", a->name, data->entry);
			return (FETCH_ERROR);
		}
	} while (!S_ISREG(sb.st_mode));
	log_debug("%s: retrieving mail from: %s", a->name, data->entry);

	if (sb.st_size == 0) {
		log_warnx("%s: %s: empty file", a->name, data->entry); 
		return (FETCH_ERROR);
	}
	if (sb.st_size > conf.max_size)
		return (FETCH_OVERSIZE);
	
	if ((fd = open(data->entry, O_RDONLY, 0)) < 0) {
		log_warn("%s: %s: stat", a->name, data->entry);
		return (FETCH_ERROR);
	}			
	
	init_mail(m, sb.st_size);
	m->s = xstrdup(basename(data->path));

	log_debug("%s: reading %zu bytes", a->name, m->size);
	if (read(fd, m->data, sb.st_size) != sb.st_size) {
		log_warn("%s: %s: read", a->name, data->entry); 
		return (FETCH_ERROR);
	}
	
	/* find the body */
	m->body = -1;
	ptr = m->data;
	end = m->data + m->size;
	while ((ptr = memchr(ptr, '\n', end - ptr)) != NULL) {
		ptr++;
		if (ptr < end && *ptr == '\n') {
			ptr++;
			if (ptr != end)
				m->body = ptr - m->data;
			break;
		}
	}
	
	return (FETCH_SUCCESS);
}

int
maildir_delete(struct account *a)
{
	struct maildir_data	*data = a->data;

	if (unlink(data->entry) != 0)
		return (1);

	return (0);
}

int
maildir_disconnect(struct account *a)
{
	struct maildir_data	*data = a->data;

	if (data->entry != NULL)
		xfree(data->entry);

	if (data->dirp != NULL)
		closedir(data->dirp);
	if (data->path != NULL)
		xfree(data->path);

	return (0);
}

char *
maildir_desc2(struct account *a)
{
	struct maildir_data	*data = a->data;
	char			*buf, *s;
	size_t			 slen, len, off;
	u_int			 i;

	if (ARRAY_LENGTH(data->paths) == 1) {
		s = ARRAY_ITEM(data->paths, 0, char *);
		xasprintf(&buf, "maildir \"%s\"", s);
		return (buf);
	}

	len = 256;
        buf = xmalloc(len + 1);
	off = strlcpy(buf, "maildirs {", len);

	for (i = 0; i < ARRAY_LENGTH(data->paths); i++) {
		s = ARRAY_ITEM(data->paths, 0, char *);
		slen = strlen(s);

		ENSURE_SIZE(buf, len, off + slen + 3);
		buf[off++] = ' ';
		buf[off++] = '"';		
		memcpy(buf + off, s, slen);
		off += slen;
		buf[off++] = '"';
	}
	ENSURE_SIZE(buf, len, off + 3);
	buf[off++] = ' ';
	buf[off++] = '}';
	buf[off] = '\0';

	return (buf);
}
