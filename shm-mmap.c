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
#include <setjmp.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

#ifdef SHM_MMAP

/*
 * This implements shared memory using mmap'd files in TMPDIR.
 */

#define SHM_PROT PROT_READ|PROT_WRITE

void	shm_sighandler(int);

int	shm_verify(char *, size_t, size_t);
int	shm_expand(struct shm *, size_t);

int	failed;
jmp_buf	jb;

void
shm_sighandler(int sig)
{
	if (sig == SIGSEGV || sig == SIGBUS)
		longjmp(jb, 1);
}

/* Verify mmap'd range is available. */
int
shm_verify(char *base, size_t offset, size_t size)
{
	struct sigaction	 act;
	char			*ptr;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	act.sa_handler = shm_sighandler;
	if (sigaction(SIGSEGV, &act, NULL) < 0)
		fatal("sigaction");
	if (sigaction(SIGBUS, &act, NULL) < 0)
		fatal("sigaction");

	/*
	 * Fill the buffer and check for SIGBUS or SIGSEGV.
	 */
	failed = 0;
	if (setjmp(jb) == 0) {
		for (ptr = base + offset; ptr < base + offset + size; ptr++)
			*ptr = 0xff;
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

	/*
	 * Sync the region. This'll hopefully complain if there isn't enough
	 * disk space.
	 */
	if (msync(base + offset, size, MS_SYNC) != 0)
		return (1);

	return (0);
}

/* Expand or reduce shm file to size. */
int
shm_expand(struct shm *shm, size_t size)
{
	char	c;

	if (size == shm->size)
		return (0);

	if (size < shm->size)
		return (ftruncate(shm->fd, size) != 0);

	if (lseek(shm->fd, size, SEEK_SET) == -1)
		return (1);
	c = '\0';
	if (write(shm->fd, &c, 1) == -1)
		return (1);
	return (0);
}

/* Create an shm file and map it. */
void *
shm_create(struct shm *shm, size_t size)
{
	int	error;

        if (size == 0)
                fatalx("shm_malloc: zero size");

	if (printpath(shm->name, sizeof shm->name,
	    "%s/%s.XXXXXXXXXX", conf.tmp_dir, __progname) != 0)
		return (NULL);
	if ((shm->fd = mkstemp(shm->name)) < 0)
		return (NULL);

	if (shm_expand(shm, size) != 0)
		goto error;

	shm->data = mmap(NULL, size, SHM_PROT, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		goto error;
	madvise(shm->data, size, MADV_SEQUENTIAL);

	if (shm_verify(shm->data, 0, shm->size) != 0) {
		error = errno;
		if (munmap(shm->data, shm->size) != 0)
			fatal("munmap");
		errno = error;
		goto error;
	}

	shm->size = size;
	return (shm->data);

error:
	error = errno;
	unlink(shm->name);
	errno = error;
	return (NULL);
}

/* Destroy shm file. */
void
shm_destroy(struct shm *shm)
{
	shm_close(shm);

	if (unlink(shm->name) != 0)
		fatal("unlink");
	*shm->name = '\0';
}

/* Close and unmap shm without destroying file. */
void
shm_close(struct shm *shm)
{
	if (munmap(shm->data, shm->size) != 0)
		fatal("munmap");
	shm->data = NULL;

	close(shm->fd);
	shm->fd = -1;
}

/* Reopen and map shm file. */
void *
shm_reopen(struct shm *shm)
{
	if ((shm->fd = open(shm->name, O_RDWR, 0)) < 0)
		return (NULL);

	shm->data = mmap(NULL, shm->size, SHM_PROT, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		return (NULL);
	madvise(shm->data, shm->size, MADV_SEQUENTIAL);

	return (shm->data);
}

/* Set ownership of shm file. */
int
shm_owner(struct shm *shm, uid_t uid, gid_t gid)
{
	if (fchown(shm->fd, uid, gid) != 0)
		return (1);

	return (0);
}

/* Resize an shm file. */
void *
shm_resize(struct shm *shm, size_t nmemb, size_t size)
{
	size_t	 newsize = nmemb * size;

	if (size == 0)
                fatalx("shm_realloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("shm_realloc: nmemb * size > SIZE_MAX");

	if (munmap(shm->data, shm->size) != 0)
		fatal("munmap");
	shm->data = NULL;

	if (shm_expand(shm, newsize) != 0)
		return (NULL);

	shm->data = mmap(NULL, newsize, SHM_PROT, MAP_SHARED, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		return (NULL);
	madvise(shm->data, newsize, MADV_SEQUENTIAL);

	if (shm_verify(shm->data, shm->size, newsize - shm->size) != 0)
		return (NULL);

	shm->size = newsize;
	return (shm->data);
}

#endif /* SHM_MMAP */
