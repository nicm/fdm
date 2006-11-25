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

const char	*entries[] = { "cur", "new", NULL };

struct fetch	 fetch_maildir = { { NULL, NULL },
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
	data->ep = NULL;

	return (0);
}

int
maildir_poll(struct account *a, u_int *n)
{
	struct maildir_data	*data = a->data;
	u_int			 i;
	char			*s, path[MAXPATHLEN];
	DIR			*dirp;
	struct dirent		*dp;
	struct stat		 sb;
	const char	       **ep;

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

		for (ep = entries; *ep != NULL; ep++) {
			if (xsnprintf(path, sizeof path, "%s/%s", s, *ep) < 0) {
				log_warn("%s: %s: xsnprintf", a->name, s);
				xfree(s);
				return (POLL_ERROR);
			}			
			if ((dirp = opendir(path)) == NULL) {
				log_warn("%s: %s: opendir", a->name, path);
				xfree(s);
				return (POLL_ERROR);
			}
			
			while ((dp = readdir(dirp)) != NULL) {
				if (xsnprintf(path, sizeof path, "%s/%s/%s", 
				    s, *ep, dp->d_name) < 0) {
					log_warn("%s: %s: xsnprintf", a->name,
					    path);
					closedir(dirp);
					xfree(s);
					return (POLL_ERROR);
				}
				if (stat(path, &sb) != 0) {
					log_warn("%s: %s: stat", a->name, path);
					closedir(dirp);
					xfree(s);
					return (POLL_ERROR);
				}
				if (!S_ISREG(sb.st_mode))
					continue;
				
				(*n)++;
			}
			
			closedir(dirp);
		}

		xfree(s);
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
		if (data->ep == NULL || *data->ep == NULL) {
			s = ARRAY_ITEM(data->paths, data->index, char *);
			data->path = replaceinfo(s, a, NULL, NULL);
			if (data->path == NULL || *data->path == '\0') {
				log_warnx("%s: empty path", a->name);
				return (FETCH_ERROR);
			}
			log_debug("%s: opening maildir: %s", a->name,
			    data->path);
			data->ep = entries;
		}

		xasprintf(&s, "%s/%s", data->path, *data->ep);
		log_debug("%s: examining subdirectory: %s", a->name, *data->ep);
		if ((data->dirp = opendir(s)) == NULL) {
			log_warn("%s: %s: opendir", a->name, data->path);
			xfree(s);
			return (FETCH_ERROR);
		}
		xfree(s);
	}

	do {
		dp = readdir(data->dirp);
		if (dp == NULL) {
			closedir(data->dirp);
			data->dirp = NULL;	

			data->ep++;
			if (*data->ep == NULL) {
				xfree(data->path);
				data->path = NULL;

				data->index++;
				if (data->index == ARRAY_LENGTH(data->paths))
					return (FETCH_COMPLETE);
			}
			goto restart;
		}

		if (data->entry != NULL)
			xfree(data->entry);
		xasprintf(&data->entry, "%s/%s/%s", data->path, *data->ep,
		    dp->d_name);
		if (stat(data->entry, &sb) != 0) {
			log_warn("%s: %s: stat", a->name, data->entry);
			return (FETCH_ERROR);
		}
	} while (!S_ISREG(sb.st_mode));
	log_debug2("%s: reading mail from: %s", a->name, data->entry);

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

	log_debug2("%s: reading %zu bytes", a->name, m->size);
	if (read(fd, m->data, sb.st_size) != sb.st_size) {
		close(fd);
		log_warn("%s: %s: read", a->name, data->entry); 
		return (FETCH_ERROR);
	}
	close(fd);

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

	if (unlink(data->entry) != 0) {
		log_warn("%s: %s: unlink", a->name, data->entry);
		return (1);
	}

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
		s = ARRAY_ITEM(data->paths, i, char *);
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
