/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "fdm.h"

struct cache *
cache_open(char *path, char **cause)
{
	struct cache	*cc;

	cc = xmalloc(sizeof *cc);
	cc->path = path;
	cc->flags = 0;
	
	ARRAY_INIT(&cc->list);
	cc->data = NULL;
	cc->space = cc->size = 0;

	cc->fd = open(cc->path, O_RDWR, 0);
	if (cc->fd < 0) {
		if (errno != ENOENT) {
			xasprintf(cause, "%s: %s", cc->path, strerror(errno));
 			xfree(cc);
			return (NULL);
		}

		cc->fd = open(cc->path, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
		if (cc->fd < 0) {
			xasprintf(cause, "%s: %s", cc->path, strerror(errno));
 			xfree(cc);
			return (NULL);
		}

		cc->flags |= CACHE_NEW;
	}
	
	return (cc);
}

int
cache_load(struct cache *cc, char **cause)
{
	struct cachehdr	 hdr;
	ssize_t		 error;
	size_t		 size;

	*cause = NULL;

	if (cc->flags & CACHE_NEW) {
		cc->flags &= ~CACHE_NEW;
		return (0);
	}

	if (lseek(cc->fd, 0, SEEK_SET) < 0)
		goto error;

	if ((error = read(cc->fd, &hdr, sizeof hdr)) != sizeof hdr) {
		if (error < 0)
			goto error;
		goto invalid;
	}
	if (letoh32(hdr.version) != CACHE_VERSION) {
		xasprintf(cause, "%s: unknown cache version: %.08x", cc->path,
		    hdr.version);
		goto error;
	}
	if (letoh64(hdr.size) > SIZE_MAX)
		goto invalid;
	if (letoh32(hdr.entries) > UINT_MAX)
		goto invalid;

	cc->list.num = letoh32(hdr.entries);
 	if (cc->list.num > 0) {
		size = sizeof (struct cacheent);
		cc->list.list = xcalloc(cc->list.num, size);
		size *= cc->list.num;
		error = read(cc->fd, cc->list.list, size);
		if (error < 0 || (size_t) error != size) {
			if (error < 0)
				goto error;
			goto invalid;
		}

		cc->space = cc->size = letoh64(hdr.size);
		if (cc->size == 0)
			goto invalid;
		cc->data = xmalloc(cc->size);
		error = read(cc->fd, cc->data, cc->size);
		if (error < 0 || (size_t) error != cc->size) {
			if (error < 0)
				goto error;
			goto invalid;
		}
	}

	return (0);

invalid:
	xasprintf(cause, "%s: invalid or corrupted cache", cc->path);
	
error:
	if (*cause == NULL)
		xasprintf(cause, "%s: %s", cc->path, strerror(errno));
	return (1);
}

int
cache_save(struct cache *cc, char **cause)
{
	struct cachehdr	 hdr;
	ssize_t		 error;
	size_t		 size;
	off_t		 used;

	*cause = NULL;

	if (lseek(cc->fd, 0, SEEK_SET) < 0)
		goto error;

	used = 0;

	hdr.version = htole32(CACHE_VERSION);
	hdr.entries = htole32(ARRAY_LENGTH(&cc->list));
	hdr.size = htole64(cc->size);
	if ((error = write(cc->fd, &hdr, sizeof hdr)) != sizeof hdr) {
		if (error < 0)
			goto error;
		goto failed;
	}
	used += sizeof hdr;

	if (!ARRAY_EMPTY(&cc->list)) {
		size = ARRAY_LENGTH(&cc->list) * sizeof (struct cacheent);
		error = write(cc->fd, cc->list.list, size);
		if (error < 0 || (size_t) error != size) {
			if (error < 0)
				goto error;
			goto failed;
		}
		used += size;
		
		error = write(cc->fd, cc->data, cc->size);
		if (error < 0 || (size_t) error != cc->size) {
			if (error < 0)
				goto error;
			goto failed;
		}
		used += cc->size;
	}		

	if (ftruncate(cc->fd, used) < 0)
		goto error;
	if (fsync(cc->fd) < 0)
		goto error;

	return (0);

failed:
	xasprintf(cause, "%s: failed to save cache", cc->path);

error:
	if (*cause == NULL)
		xasprintf(cause, "%s: %s", cc->path, strerror(errno));
	return (1);
}

void
cache_close(struct cache *cc)
{
	close(cc->fd);

	ARRAY_FREE(&cc->list);
	if (cc->data != NULL)
		xfree(cc->data);

	xfree(cc->path);
	xfree(cc);
}

int
cache_compact(struct cache *cc, time_t age)
{
	return (0);
}

void
cache_add(struct cache *cc, char *item)
{
	struct cacheent	*ent;
	time_t		 t;

	ARRAY_EXTEND(&cc->list, 1, struct cacheent);
	ent = &ARRAY_LAST(&cc->list, struct cacheent);
	memset(ent, 0, sizeof *ent);

	t = time(NULL);

	ent->flags = 0;
	ent->added = htole64(t);
	
	ent->off = htole64(cc->size);
	ent->size = strlen(item) + 1;

	ENSURE_FOR(cc->data, cc->space, cc->size, ent->size);
	memcpy(cc->data + cc->size, item, ent->size - 1);
	cc->size += ent->size;
	cc->data[cc->size - 1] = '\0';
}

int
cache_contains(struct cache *cc, char *item)
{
 	struct cacheent	*ce;
	u_int		 i;

	for (i = 0; i < ARRAY_LENGTH(&cc->list); i++) {
		ce = &ARRAY_ITEM(&cc->list, i, struct cacheent);
		if (ce->flags & CACHEENT_UNUSED)
			continue;

		if (strcmp(item, cc->data + ce->off) == 0)
			return (1);
	}

	return (0);
}
