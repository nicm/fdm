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
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

/*
 * This implements a sort of shared memory using mmap'd files in TMPDIR.
 */

#define SHM_PROTW PROT_READ|PROT_WRITE
#define SHM_PROTR PROT_READ

int	failed;
jmp_buf	jb;

void	shm_sighandler(int);
int	shm_test(void *, size_t, int);

void
shm_sighandler(int sig)
{
	if (sig == SIGSEGV || sig == SIGBUS)
		longjmp(jb, 1);
}

int
shm_test(void *base, size_t size, int wr)
{
	struct sigaction	 act;
	char			*ptr;
	volatile char		 c;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	act.sa_handler = shm_sighandler;
	if (sigaction(SIGSEGV, &act, NULL) < 0)
		fatal("sigaction");
	if (sigaction(SIGBUS, &act, NULL) < 0)
		fatal("sigaction");

	/*
	 * We check the mapped area by writing to/reading from the area and
	 * checking for SIGSEGV or SIGBUS.
	 */
	failed = 0;
	if (setjmp(jb) == 0) {
		if (wr) {
			for (ptr = base; ptr < ((char *) base) + size; ptr++)
				*ptr = 0xff;
		} else {
			for (ptr = base; ptr < ((char *) base) + size; ptr++)
				c = *ptr;
		}
	} else
		failed = 1;

	act.sa_handler = SIG_DFL;
	if (sigaction(SIGSEGV, &act, NULL) < 0)
		fatal("sigaction");
	if (sigaction(SIGBUS, &act, NULL) < 0)
		fatal("sigaction");

	if (failed) {
		errno = ENOMEM;
		return (1);
	}

	if (msync(base, size, MS_SYNC) != 0)
		return (1);
 
	return (0);
}

void *
shm_reopen(struct shm *shm)
{
#ifdef SHM_DEBUG
	log_debug("shm_reopen: %s", shm->name);
#endif

	if ((shm->fd = open(shm->name, O_RDWR, 0)) < 0)
		return (NULL);

	shm->data = mmap(NULL, shm->size, SHM_PROTW, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		return (NULL);
	madvise(shm->data, shm->size, MADV_SEQUENTIAL);

	if (shm_test(shm->data, shm->size, 0) != 0)
		return (NULL);

	return (shm->data);
}

void *
shm_malloc(struct shm *shm, size_t size)
{
	int	error;
	char	c;

        if (size == 0)
                fatalx("shm_malloc: zero size");

	if (printpath(shm->name, sizeof shm->name,
	    "%s/%s.XXXXXXXXXX", conf.tmp_dir, __progname) != 0)
		return (NULL);
	if ((shm->fd = mkstemp(shm->name)) < 0)
		return (NULL);

#ifdef SHM_DEBUG
	log_debug("shm_malloc: %s", shm->name);
#endif

	if (lseek(shm->fd, size, SEEK_SET) < 0)
		goto error;
	c = '\0';
	if (write(shm->fd, &c, 1) < 0)
		goto error;

	shm->data = mmap(NULL, size, SHM_PROTW, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		goto error;
	madvise(shm->data, size, MADV_SEQUENTIAL);

	if (shm_test(shm->data, size, 1) != 0)
		goto error;
	shm->size = size;

	return (shm->data);

error:
	error = errno;
	unlink(shm->name);
	errno = error;
	return (NULL);
}

void *
shm_realloc(struct shm *shm, size_t nmemb, size_t size)
{
	size_t	 newsize = nmemb * size;
	char	*base, c;

#ifdef SHM_DEBUG
	log_debug("shm_realloc: %s: %zu -> %zu", shm->name, shm->size, newsize);
#endif

	if (newsize == shm->size)
		return (shm->data);
	
	if (size == 0)
                fatalx("shm_realloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("shm_realloc: nmemb * size > SIZE_MAX");

	if (munmap(shm->data, shm->size) != 0)
		fatal("munmap");
	shm->data = NULL;

	if (newsize < shm->size) {
		if (ftruncate(shm->fd, newsize) != 0)
			return (NULL);
	} else {
		if (lseek(shm->fd, newsize, SEEK_SET) < 0)
			return (NULL);
		c = '\0';
		if (write(shm->fd, &c, 1) < 0)
			return (NULL);
	}

	shm->data = mmap(NULL, newsize, SHM_PROTW, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		return (NULL);
	madvise(shm->data, newsize, MADV_SEQUENTIAL);

	if (newsize > shm->size) {
		base = shm->data;
		if (shm_test(base + shm->size, newsize - shm->size, 1) != 0) {
			shm->size = newsize;
			return (NULL);
		}
	}
	shm->size = newsize;

	return (shm->data);
}

void
shm_free(struct shm *shm)
{
#ifdef SHM_DEBUG
	log_debug("shm_free: %s", shm->name);
#endif

	if (shm->fd == -1)
		return;

	if (shm->data != NULL && munmap(shm->data, shm->size) != 0)
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
	log_debug("%ld shm_destroy: %s", (long) getpid(), shm->name);
#endif

	shm_free(shm);
	if (unlink(shm->name) != 0)
		fatal("unlink");
}
