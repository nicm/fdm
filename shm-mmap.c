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
#include <string.h>
#include <unistd.h>

#include "fdm.h"

/*
 * This implements shared memory using mmap'd files in TMPDIR.
 */

int	shm_expand(struct shm *, size_t);

char	shm_block[BUFSIZ];

#ifdef MAP_NOSYNC
#define SHM_FLAGS MAP_SHARED|MAP_NOSYNC
#else
#define SHM_FLAGS MAP_SHARED
#endif
#define SHM_PROT PROT_READ|PROT_WRITE

/* Work out shm path. */
char *
shm_path(struct shm *shm)
{
	static char	path[MAXPATHLEN];

	if (mkpath(path, sizeof path, "%s/%s", conf.tmp_dir, shm->name) != 0)
		return (NULL);
	return (path);
}

/* Expand or reduce shm file to size. */
int
shm_expand(struct shm *shm, size_t size)
{
	ssize_t	n;

	if (size == shm->size)
		return (0);

	if (size < shm->size)
		return (ftruncate(shm->fd, size) != 0);

	if (lseek(shm->fd, shm->size, SEEK_SET) == -1)
		return (-1);

	/*
	 * Fill the file using write(2) to avoid fragmentation problems on
	 * FreeBSD and also to detect disk full.
	 */
	while (size > sizeof shm_block) {
		if ((n = write(shm->fd, shm_block, sizeof shm_block)) == -1)
			return (-1);
		if (n != sizeof shm_block) {
			errno = EIO;
			return (-1);
		}
		size -= sizeof shm_block;
	}
	if (size > 0) {
		if ((n = write(shm->fd, shm_block, size)) == -1)
			return (-1);
		if ((size_t) n != size) {
			errno = EIO;
			return (-1);
		}
	}

	/*
	 * Sync the fd, should hopefully fail if disk full.
	 */
	if (fsync(shm->fd) != 0)
		return (-1);

	return (0);
}

/* Create an shm file and map it. */
void *
shm_create(struct shm *shm, size_t size)
{
	int	 saved_errno;
	char	*path;

        if (size == 0)
                fatalx("zero size");

	if (mkpath(
	    shm->name, sizeof shm->name, "%s.XXXXXXXXXX", __progname) != 0)
		return (NULL);
	if ((path = shm_path(shm)) == NULL)
		return (NULL);
	if ((shm->fd = mkstemp(path)) == -1)
		return (NULL);
	strlcpy(shm->name, xbasename(path), sizeof shm->name);

	if (shm_expand(shm, size) != 0)
		goto error;

	shm->data = mmap(NULL, size, SHM_PROT, SHM_FLAGS, shm->fd, 0);
	if (shm->data == MAP_FAILED)
		goto error;
	madvise(shm->data, size, MADV_SEQUENTIAL);

	shm->size = size;
	return (shm->data);

error:
	saved_errno = errno;
	unlink(path);
	errno = saved_errno;
	return (NULL);
}

/* Destroy shm file. */
void
shm_destroy(struct shm *shm)
{
	char	*path;

	if (*shm->name == '\0')
		return;

	shm_close(shm);

	if ((path = shm_path(shm)) == NULL)
		fatal("unlink failed");
	if (unlink(path) != 0)
		fatal("unlink failed");

	*shm->name = '\0';
}

/* Close and unmap shm without destroying file. */
void
shm_close(struct shm *shm)
{
	if (shm->fd == -1)
		return;

	if (munmap(shm->data, shm->size) != 0)
		fatal("munmap failed");
	shm->data = NULL;

	close(shm->fd);
	shm->fd = -1;
}

/* Reopen and map shm file. */
void *
shm_reopen(struct shm *shm)
{
	char	*path;

	if ((path = shm_path(shm)) == NULL)
		return (NULL);
	if ((shm->fd = open(path, O_RDWR, 0)) == -1)
		return (NULL);

	shm->data = mmap(NULL, shm->size, SHM_PROT, SHM_FLAGS, shm->fd, 0);
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
		return (-1);

	return (0);
}

/* Resize an shm file. */
void *
shm_resize(struct shm *shm, size_t nmemb, size_t size)
{
	size_t	 newsize = nmemb * size;

	if (size == 0)
                fatalx("zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("nmemb * size > SIZE_MAX");

#ifndef WITH_MREMAP
	if (munmap(shm->data, shm->size) != 0)
		fatal("munmap failed");
	shm->data = NULL;
#endif

	if (shm_expand(shm, newsize) != 0)
		return (NULL);

#ifdef WITH_MREMAP
	shm->data = mremap(shm->data, shm->size, newsize, MREMAP_MAYMOVE);
#else
	shm->data = mmap(NULL, newsize, SHM_PROT, SHM_FLAGS, shm->fd, 0);
#endif
	if (shm->data == MAP_FAILED)
		return (NULL);
	madvise(shm->data, newsize, MADV_SEQUENTIAL);

	shm->size = newsize;
	return (shm->data);
}
