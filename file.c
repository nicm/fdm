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

int	mklock(u_int, const char *);
void	rmlock(u_int, const char *);
int	lockfd(u_int, int);

/* Make path into buffer. */
int
mkpath(char *buf, size_t len, const char *fmt, ...)
{
	va_list	ap;
	int	n;

	va_start(ap, fmt);
	n = vmkpath(buf, len, fmt, ap);
	va_end(ap);

	return (n);
}

/* Make path into buffer. */
int
vmkpath(char *buf, size_t len, const char *fmt, va_list ap)
{
	if ((size_t) xvsnprintf(buf, len, fmt, ap) >= len) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (0);
}

/* Make lock file. */
int
mklock(u_int locks, const char *path)
{
	char	lock[MAXPATHLEN];
	int	fd;

	if (!(locks & LOCK_DOTLOCK))
		return (0);

	if (mkpath(lock, sizeof lock, "%s.lock", path) != 0)
		return (-1);

	fd = xcreate(lock, O_WRONLY, -1, -1, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		if (errno == EEXIST)
			errno = EAGAIN;
		return (-1);
	}
	close(fd);

	cleanup_register(lock);
	return (0);
}

/* Remove lock file. */
void
rmlock(u_int locks, const char *path)
{
	char	lock[MAXPATHLEN];

	if (!(locks & LOCK_DOTLOCK))
		return;

	if (mkpath(lock, sizeof lock, "%s.lock", path) != 0)
		log_fatal("unlink");

	if (unlink(lock) != 0)
		log_fatal("unlink");

	cleanup_deregister(lock);
}

/* Lock file descriptor. */
int
lockfd(u_int locks, int fd)
{
	struct flock	fl;

	if (locks & LOCK_FLOCK) {
		if (flock(fd, LOCK_EX|LOCK_NB) != 0) {
			if (errno == EWOULDBLOCK)
				errno = EAGAIN;
			return (-1);
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
			return (-1);
		}
	}

	return (0);
}

/*
 * Open a file, locking using the lock types specified. Returns EAGAIN if lock
 * failed.
 */
int
openlock(const char *path, int flags, u_int locks)
{
	int	fd, saved_errno;

	if (mklock(locks, path) != 0)
		return (-1);
	if ((fd = open(path, flags, 0)) == -1)
		goto error;
	if (lockfd(locks, fd) != 0)
		goto error;

	return (fd);

error:
	saved_errno = errno;
	close(fd);
	rmlock(locks, path);
	errno = saved_errno;
	return (-1);
}

/* Create a locked file. */
int
createlock(
    const char *path, int flags, uid_t uid, gid_t gid, mode_t mode, u_int locks)
{
	int	fd, saved_errno;

	if (mklock(locks, path) != 0)
		return (-1);
	if ((fd = xcreate(path, flags, uid, gid, mode)) == -1)
		goto error;
	if (lockfd(locks, fd) != 0)
		goto error;

	return (fd);

error:
	saved_errno = errno;
	close(fd);
	rmlock(locks, path);
	errno = saved_errno;
	return (-1);
}

/* Close locked file and remove locks. */
void
closelock(int fd, const char *path, u_int locks)
{
	close(fd);
	rmlock(locks, path);
}

/* Create a file. */
int
xcreate(const char *path, int flags, uid_t uid, gid_t gid, mode_t mode)
{
	int	fd;

	if ((fd = open(path, flags|O_CREAT|O_EXCL, mode)) == -1)
		return (-1);
	if (uid != (uid_t) -1 || gid != (gid_t) -1) {
		if (fchown(fd, uid, gid) != 0)
			return (-1);
	}

	return (fd);
}

/* Make a directory. */
int
xmkdir(const char *path, uid_t uid, gid_t gid, mode_t mode)
{
	if (mkdir(path, mode) != 0)
		return (-1);

	if (uid != (uid_t) -1 || gid != (gid_t) -1) {
		if (chown(path, uid, gid) != 0)
			return (-1);
	}

	return (0);
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
