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

#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fdm.h"

int
openlock(char *path, u_int locks, int flags, mode_t mode)
{
	char		*lock;
	int	 	 fd;
	struct flock	 fl;

	if (locks & LOCK_DOTLOCK) {
		xasprintf(&lock, "%s.lock", path);
		if ((fd = open(lock, O_WRONLY|O_CREAT|O_EXCL)) != 0) {
			if (errno == EEXIST) {
				errno = EAGAIN;
				return (-1);
			}
			return (-1);
		}
		close(fd);
	}
	if (locks & LOCK_FLOCK)
		flags |= O_EXLOCK;

	fd = open(path, flags, mode);
	
	if (fd != -1 && locks & LOCK_FCNTL) {
		memset(&fl, 0, sizeof fl);
		fl.l_start = 0;
		fl.l_len = 0;
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		if (fcntl(fd, F_SETLK, fl) == -1) {
			if (locks & LOCK_DOTLOCK)
				unlink(lock);
			/* fcntl returns EAGAIN if locked */
			return (-1);		
		}
	}

	return (fd);
}

void
closelock(int fd, char *path, u_int locks)
{
	char	*lock;

	if (locks & LOCK_DOTLOCK) {
		xasprintf(&lock, "%s.lock", path);
		unlink(lock);
	}

	close(fd);
}

int
has_from(struct mail *m)
{
	if (m->data == NULL)
		return (0);
	return (m->size >= 5 && strncmp(m->data, "From ", 5) == 0);
}
    
void
trim_from(struct mail *m)
{
	char	*ptr;

	if (!has_from(m))
		return;
	
	ptr = memchr(m->data, '\n', m->size);
	if (ptr == NULL)
		ptr = m->data + m->size;
	else
		ptr++;

	m->size -= ptr - m->data;		
	memmove(m->data, ptr, m->size);
}

void
insert_from(struct mail *m)
{
	char 	*from;
	size_t	 len;
	time_t	 t;

	if (has_from(m))
		return;

	/* fake it up using local user */ /* XXX */
	t = time(NULL);
	len = xasprintf(&from, "From %s %s", conf.user, ctime(&t));

	ENSURE_SIZE(m->data, m->space, m->size + len);
	memmove(m->data + len, m->data, m->size);
	memcpy(m->data, from, len);
	m->size += len;

	xfree(from);
}
