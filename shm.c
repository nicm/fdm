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
#include <paths.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

#undef SHM_DEBUG

void *
shm_reopen(struct shm *shm)
{
#ifdef SHM_DEBUG
	log_debug("shm_reopen: %s", shm->name);
#endif

	if ((shm->fd = open(shm->name, O_RDWR, 0)) < 0)
		fatal("open");

	shm->data = mmap(NULL, shm->size, PROT_READ|PROT_WRITE, MAP_SHARED, 
	    shm->fd, 0);
	if (shm->data == MAP_FAILED)
		fatal("mmap");

	return (shm->data);
}

void *
shm_malloc(struct shm *shm, size_t size)
{
	char	c[1];

        if (size == 0)
                fatalx("shm_malloc: zero size");

	/* XXX TMPDIR XXX check free space */
	xsnprintf(shm->name, sizeof shm->name, _PATH_TMP "%s.XXXXXXXXXXXX", 
	    __progname);
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

	shm->data = mmap(NULL, shm->size, PROT_READ|PROT_WRITE, MAP_SHARED, 
	    shm->fd, 0);
	if (shm->data == MAP_FAILED)
		fatal("mmap");

	return (shm->data);
}

void *
shm_realloc(struct shm *shm, size_t nmemb, size_t size)
{
	char	c[1];

#ifdef SHM_DEBUG
	log_debug("shm_realloc: %s", shm->name);
#endif

	if (size == 0)
                fatalx("shm_realloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("shm_realloc: nmemb * size > SIZE_MAX");

	if (size < shm->size) {
		if (ftruncate(shm->fd, size) != 0)
			fatal("ftruncate");
	} else {
		if (lseek(shm->fd, size, SEEK_SET) < 0)
			fatal("lseek");

		c[0] = '\0';
		if (write(shm->fd, c, 1) < 0)
			fatal("write");
	}
	shm->size = size;
	
	shm->data = mmap(NULL, shm->size, PROT_READ|PROT_WRITE, MAP_SHARED, 
	    shm->fd, 0);
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
