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
#include <sys/mman.h>

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

#undef SHM_DEBUG

#define SHM_PROTW PROT_READ|PROT_WRITE
#define SHM_PROTR PROT_READ

void *
shm_reopen(struct shm *shm)
{
#ifdef SHM_DEBUG
	log_debug("shm_reopen: %s", shm->name);
#endif

	if ((shm->fd = open(shm->name, O_RDWR, 0)) < 0)
		fatal("open");

	shm->data = mmap(NULL, shm->size, SHM_PROTW, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		fatal("mmap");
	madvise(shm->data, shm->size, MADV_SEQUENTIAL);

	return (shm->data);
}

void *
shm_malloc(struct shm *shm, size_t size)
{
	char	c[1];

        if (size == 0)
                fatalx("shm_malloc: zero size");

	if (xsnprintf(shm->name, sizeof shm->name, "%s/%s.XXXXXXXXXX",
	    conf.tmp_dir, __progname) < 0)
		fatal("xsnprintf");
	if ((shm->fd = mkstemp(shm->name)) < 0)
		fatal("mkstemp");

#ifdef SHM_DEBUG
	log_debug("shm_malloc: %s", shm->name);
#endif

	shm->size = size;
	if (lseek(shm->fd, size, SEEK_SET) < 0)
		fatal("lseek");

	c[0] = '\0';
	if (write(shm->fd, c, 1) < 0)
		fatal("write");

	shm->data = mmap(NULL, shm->size, SHM_PROTW, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		fatal("mmap");
	madvise(shm->data, shm->size, MADV_SEQUENTIAL);

	return (shm->data);
}

void *
shm_realloc(struct shm *shm, size_t nmemb, size_t size)
{
	size_t	newsize = nmemb * size;
	char	c[1];

#ifdef SHM_DEBUG
	log_debug("shm_realloc: %s: %zu -> %zu", shm->name, shm->size, newsize);
#endif

	if (size == 0)
                fatalx("shm_realloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("shm_realloc: nmemb * size > SIZE_MAX");

	if (newsize < shm->size) {
		if (ftruncate(shm->fd, newsize) != 0)
			fatal("ftruncate");
	} else {
		if (lseek(shm->fd, newsize, SEEK_SET) < 0)
			fatal("lseek");

		c[0] = '\0';
		if (write(shm->fd, c, 1) < 0)
			fatal("write");
	}

	shm->size = newsize;
	shm->data = mmap(NULL, shm->size, SHM_PROTW, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		fatal("mmap");

	return (shm->data);
}

void
shm_free(struct shm *shm)
{
#ifdef SHM_DEBUG
	log_debug("shm_free: %s", shm->name);
#endif

	if (munmap(shm->data, shm->size) != 0)
		fatal("munmap");

	shm->data = NULL;
	shm->size = 0;

	close(shm->fd);
	shm->fd = -1;
}

void
shm_destroy(struct shm *shm)
{
#ifdef SHM_DEBUG
	log_debug("shm_destroy: %s", shm->name);
#endif

	shm_free(shm);
	unlink(shm->name);
}
