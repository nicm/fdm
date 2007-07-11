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
#include <sys/file.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

/*
 * Open a file, locking using the lock types specified. Returns EAGAIN if lock
 * failed.
 */
int
openlock(const char *path, u_int locks, int flags, mode_t mode)
{
	char		*lock;
	int	 	 fd, error;
	struct flock	 fl;

	if (locks & LOCK_DOTLOCK) {
		xasprintf(&lock, "%s.lock", path);
 		fd = open(lock, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
		if (fd == -1) {
			if (errno == EEXIST)
				errno = EAGAIN;
			xfree(lock);
			return (-1);
		}
		close(fd);
		cleanup_register(lock);
	}

	if ((fd = open(path, flags, mode)) == -1)
		goto error;

	if (locks & LOCK_FLOCK) {
		if (flock(fd, LOCK_EX|LOCK_NB) != 0) {
			if (errno == EWOULDBLOCK)
				errno = EAGAIN;
			goto error;
		}
	}

	if (locks & LOCK_FCNTL) {
		memset(&fl, 0, sizeof fl);
		fl.l_start = 0;
		fl.l_len = 0;
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		if (fcntl(fd, F_SETLK, &fl) == -1) {
			/* fcntl already returns EAGAIN if needed. */
			goto error;
		}
	}

	if (locks & LOCK_DOTLOCK)
		xfree(lock);
	return (fd);

error:
	error = errno;
	close(fd);
	if (locks & LOCK_DOTLOCK) {
		if (unlink(lock) != 0)
			log_fatal("unlink");
		cleanup_deregister(lock);
		xfree(lock);
	}
	errno = error;
	return (-1);
}

/* Close locked file and remove locks. */
void
closelock(int fd, const char *path, u_int locks)
{
	char	*lock;

	if (locks & LOCK_DOTLOCK) {
		xasprintf(&lock, "%s.lock", path);
		if (unlink(lock) != 0)
			log_fatal("unlink");
		cleanup_deregister(lock);
		xfree(lock);
	}

	if (fd != -1)
		close(fd);
}

/* Check permissions on file and report problems. */
int
checkperms(const char *hdr, const char *path, int *exists)
{
	struct stat	sb;
	gid_t		gid;
	mode_t		mode;

	if (stat(path, &sb) != 0) {
		if (errno == ENOENT) {
			*exists = 0;
			return (0);
		}
		return (-1);
	}
	*exists = 1;

	mode = (S_ISDIR(sb.st_mode) ? DIRMODE : FILEMODE) & ~conf.file_umask;
	if ((sb.st_mode & DIRMODE) != mode) {
		log_warnx("%s: %s: bad permissions: %o%o%o, should be %o%o%o",
		    hdr, path, MODE(sb.st_mode), MODE(mode));
	}

	if (sb.st_uid != getuid()) {
		log_warnx("%s: %s: bad owner: %lu, should be %lu", hdr, path,
		    (u_long) sb.st_uid, (u_long) getuid());
	}

	gid = conf.file_group;
	if (gid == NOGRP)
		gid = getgid();
	if (sb.st_gid != gid) {
		log_warnx("%s: %s: bad group: %lu, should be %lu", hdr, path,
		    (u_long) sb.st_gid, (u_long) gid);
	}

	return (0);
}
