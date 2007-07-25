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

/* Create a file. */
int
xcreate(uid_t uid, gid_t gid, mode_t mode, int flags, const char *fmt, ...)
{
	char	path[PATH_MAX];
	va_list	ap;
	int	fd;

	va_start(ap, fmt);
	if ((size_t) xvsnprintf(path, sizeof path, fmt, ap) >= sizeof path) {
		va_end(ap);
		errno = ENAMETOOLONG;
		return (-1);
	}
	va_end(ap);

	if ((fd = open(path, flags|O_CREAT|O_EXCL, mode)) == -1)
		return (-1);

	if (uid != (uid_t) -1 || gid != (gid_t) -1) {
		if (fchown(fd, uid, gid) != 0)
			return (-1);
	}
	
	return (fd);
}

/* Open a file. */
int
xopen(int flags, const char *fmt, ...)
{
	char	path[PATH_MAX];
	va_list	ap;

	va_start(ap, fmt);
	if ((size_t) xvsnprintf(path, sizeof path, fmt, ap) >= sizeof path) {
		va_end(ap);
		errno = ENAMETOOLONG;
		return (-1);
	}
	va_end(ap);

	return (open(path, flags, 0));
}

/* Make directory. */
int
xmkdir(uid_t uid, gid_t gid, mode_t mode, const char *fmt, ...)
{
	char	path[PATH_MAX];
	va_list	ap;

	va_start(ap, fmt);
	if ((size_t) xvsnprintf(path, sizeof path, fmt, ap) >= sizeof path) {
		va_end(ap);
		errno = ENAMETOOLONG;
		return (-1);
	}
	va_end(ap);

	if (mkdir(path, mode) != 0)
		return (-1);
	if (uid != (uid_t) -1 || gid != (gid_t) -1) {
		if (chown(path, uid, gid) != 0)
			return (-1);
	}

	return (0);
}

/* Stat a file. */
int
xstat(struct stat *sb, const char *fmt, ...)
{
	char	path[PATH_MAX];
	va_list	ap;

	va_start(ap, fmt);
	if ((size_t) xvsnprintf(path, sizeof path, fmt, ap) >= sizeof path) {
		va_end(ap);
		errno = ENAMETOOLONG;
		return (-1);
	}
	va_end(ap);

	return (stat(path, sb));
}

/* Check mode of file. */
const char *
checkmode(struct stat *sb, mode_t mode)
{
	static char	msg[128];

	if ((sb->st_mode & ACCESSPERMS) == mode)
		return (NULL);

	xsnprintf(msg, sizeof msg, "bad permissions:"
	    " %o%o%o, should be %o%o%o", MODE(sb->st_mode), MODE(mode));
	return (msg);
}

/* Check owner of file. */
const char *
checkowner(struct stat *sb, uid_t uid)
{
	static char	msg[128];

	if (uid == (uid_t) -1)
		uid = getuid();
	if (sb->st_uid == uid)
		return (NULL);

	xsnprintf(msg, sizeof msg,
	    "bad owner: %lu, should be %lu", (u_long) sb->st_uid, (u_long) uid);
	return (msg);
}

/* Check group of file. */
const char *
checkgroup(struct stat *sb, gid_t gid)
{
	static char	msg[128];

	if (gid == (gid_t) -1)
		gid = getgid();
	if (sb->st_gid == gid)
		return (NULL);

	xsnprintf(msg, sizeof msg,
	    "bad group: %lu, should be %lu", (u_long) sb->st_gid, (u_long) gid);
	return (msg);
}
