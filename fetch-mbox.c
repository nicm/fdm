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
#include <sys/stat.h>
#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

int	fetch_mbox_connect(struct account *);
int	fetch_mbox_completed(struct account *);
int	fetch_mbox_fetch(struct account *, struct fetch_ctx *);
int	fetch_mbox_poll(struct account *, u_int *);
int	fetch_mbox_disconnect(struct account *, int);
void	fetch_mbox_desc(struct account *, char *, size_t);
/* XXX purge. disconnect/reconnect... */

void	fetch_mbox_free(void *);

int	fetch_mbox_makepaths(struct account *);
void	fetch_mbox_freepaths(struct account *);

int	fetch_mbox_next(struct account *, struct fetch_ctx *);
int	fetch_mbox_open(struct account *, struct fetch_ctx *);
int	fetch_mbox_mail(struct account *, struct fetch_ctx *);

struct fetch fetch_mbox = {
	"mbox",
	fetch_mbox_connect,
	NULL,
	NULL,
	fetch_mbox_completed,
	NULL,
	fetch_mbox_fetch,
	fetch_mbox_poll,
	NULL,
	NULL,
	fetch_mbox_disconnect,
	fetch_mbox_desc
};

void
fetch_mbox_free(void *ptr)
{
	struct fetch_mbox_mail	*aux = ptr;

	xfree(aux);
}

/* Make an array of all the paths to visit. */
int
fetch_mbox_makepaths(struct account *a)
{
	struct fetch_mbox_data	*data = a->data;
	char			*path;
	u_int			 i, j;
	glob_t			 g;
	struct stat		 sb;

	data->paths = xmalloc(sizeof *data->paths);
	ARRAY_INIT(data->paths);

	for (i = 0; i < ARRAY_LENGTH(data->mboxes); i++) {
		path = ARRAY_ITEM(data->mboxes, i);
		if (glob(path, GLOB_BRACE|GLOB_NOCHECK, NULL, &g) != 0) {
			log_warn("%s: glob(\"%s\")", a->name, path);
			goto error;
		}

		if (g.gl_pathc < 1)
			fatalx("glob returned garbage");
		for (j = 0; j < (u_int) g.gl_pathc; j++) {
			path = xstrdup(g.gl_pathv[j]);
			ARRAY_ADD(data->paths, path);
			if (stat(path, &sb) != 0) {
				log_warn("%s: %s", a->name, path);
				goto error;
			}
			if (S_ISDIR(sb.st_mode)) {
				errno = EISDIR;
				log_warn("%s: %s", a->name, path);
				goto error;
			}
		}
	}

	return (0);

error:
	fetch_mbox_freepaths(a);
	return (-1);
}

/* Free the array. */
void
fetch_mbox_freepaths(struct account *a)
{
	struct fetch_mbox_data	*data = a->data;
	u_int			 i;

	for (i = 0; i < ARRAY_LENGTH(data->paths); i++)
		xfree(ARRAY_ITEM(data->paths, i));

	ARRAY_FREEALL(data->paths);
}

/* Set initial state. */
int
fetch_mbox_connect(struct account *a)
{
	struct fetch_mbox_data	*data = a->data;
	
	if (fetch_mbox_makepaths(a) != 0)
		return (-1);
	data->index = 0;

	if (ARRAY_EMPTY(data->paths)) {
		log_warnx("%s: no mboxes found", a->name);
		return (-1);
	}

	data->fd = -1;
	data->base = NULL;

	data->state = fetch_mbox_open;
	return (0);
}

/* Check if all mboxes completed. */
int
fetch_mbox_completed(struct account *a)
{
	struct fetch_mbox_data	*data = a->data;

	return (data->index >= ARRAY_LENGTH(data->paths));
}

/* Clean up and free data. */
int
fetch_mbox_disconnect(struct account *a, unused int aborted)
{
	struct fetch_mbox_data	*data = a->data;

	if (data->base != NULL)
		munmap(data->base, data->size);
	if (data->fd != -1)
		closelock(data->fd, data->path, conf.lock_types);

	fetch_mbox_freepaths(a);

	return (0);
}

/* Fetch mail. */
int
fetch_mbox_fetch(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_mbox_data	*data = a->data;

	return (data->state(a, fctx));
}

/* Poll for mbox total. */
int
fetch_mbox_poll(struct account *a, u_int *n)
{
	struct fetch_mbox_data	*data = a->data;

	/* XXX */

	return (0);
}

/* Next state. Move to next mbox. */
int
fetch_mbox_next(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_mbox_data	*data = a->data;
	struct fetch_mbox_mail	*aux;
	struct mail			*m;

	/* Delete mail if any. */
	while ((m = done_mail(a, fctx)) != NULL) {
		aux = m->auxdata;
		if (m->decision != DECISION_DROP) {
			/* copy to kept list and clear ->aux to prevent free */
		}
		dequeue_mail(a, fctx);
	}

	if (!fetch_mbox_completed(a))
		data->index++;
	if (fetch_mbox_completed(a))
		return (FETCH_HOLD);

	data->state = fetch_mbox_open;
	return (FETCH_AGAIN);
}

/* Open state. */
int
fetch_mbox_open(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_mbox_data	*data = a->data;
	char			*path;
	struct stat	         sb;
	uintmax_t		 size;
	long long		 used;

	data->path = ARRAY_ITEM(data->paths, data->index);

	log_debug2("%s: trying path: %s", a->name, data->path);
	if (stat(data->path, &sb) != 0)
		goto error;
	if (S_ISDIR(sb.st_mode)) {
		errno = EISDIR;
		goto error;
	}
	if (sb.st_size < 5) {
		log_warnx("%s: %s: mbox too small", a->name, data->path);
		return (FETCH_ERROR);
	}
	size = sb.st_size;
	if (size > SIZE_MAX) {
		log_warnx("%s: %s: mbox too big", a->name, data->path);
		return (FETCH_ERROR);
	}
	data->size = size;
	
	log_debug3("%s: opening mbox, size %ju", a->name, size);
	used = 0;
	do {
		data->fd = openlock(data->path, O_RDWR, conf.lock_types);
		if (data->fd == -1) {
			if (errno == EAGAIN) {
				if (locksleep(a->name, data->path, &used) != 0)
					return (FETCH_ERROR);
				continue;
			}
			goto error;
		}
	} while (data->fd < 0);
		
	/* mmap the file. */
	data->base = mmap(
	    NULL, data->size, PROT_READ|PROT_WRITE, MAP_SHARED, data->fd, 0);
	if (data->base == MAP_FAILED) {
		close(data->fd);
		goto error;
	}

	if (strncmp(data->base, "From ", 5) != 0) {
		close(data->fd);
		log_warnx("%s: %s: not an mbox", a->name, data->path);
		return (FETCH_ERROR);
	}

	data->state = fetch_mbox_mail;
	return (FETCH_AGAIN);

error:
	log_warn("%s: %s", a->name, data->path);
	return (FETCH_ERROR);
}

/* Mail state. Find and read mail file. */
int
fetch_mbox_mail(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_mbox_data		*data = a->data;
	struct fetch_mbox_mail		*aux;
	struct mail			*m;
	
	/* XXX */
	munmap(data->base, data->size);
	data->base = NULL;
	closelock(data->fd, data->path, conf.lock_types);
	data->fd = -1;

	data->state = fetch_mbox_next;
	return (FETCH_AGAIN);
}

void
fetch_mbox_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_mbox_data	*data = a->data;
	char			*mboxes;

	mboxes = fmt_strings("mboxes ", data->mboxes);
	strlcpy(buf, mboxes, len);
	xfree(mboxes);
}
