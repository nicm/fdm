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

void
free_mail(struct mail *m)
{
	free_wrapped(m);
	if (m->from != NULL)
		xfree(m->from);
	xfree(m->base);
}

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

void
trim_from(struct mail *m)
{
	char	*ptr;
	size_t	 len;

	m->from = NULL;

	if (m->data == NULL || m->size < 5 || strncmp(m->data, "From ", 5) != 0)
		return;
	
	ptr = memchr(m->data, '\n', m->size);
	if (ptr == NULL)
		ptr = m->data + m->size;
	else
		ptr++;
	len = ptr - m->data;

	m->from = xmalloc(len + 1);
	memcpy(m->from, m->data, len);
	m->from[len] = '\0';

	m->size -= len;
	m->data += len;
	if (m->body != -1)
		m->body -= len;
}

void
make_from(struct mail *m)
{
	size_t	 len;
	time_t	 t;

	if (m->from != NULL)
		fatalx("attempt to call make_from twice");
	
	/* fake it up using local user */ /* XXX */
	t = time(NULL);
	/* XXX why no trailing \n? */
	len = xasprintf(&m->from, "From %s %s", conf.user, ctime(&t));
}

/* 
 * Sometimes mail has wrapped header lines, this undoubtedly looks neat but
 * makes them a pain to match using regexps. We build a list of all the wrapped
 * headers in m->wrapped, and can then quickly unwrap them for regexp matching
 * and wrap them again for delivery.
 */
u_int
fill_wrapped(struct mail *m)
{
	char		*ptr;
	size_t	 	 off;
	u_int		 size, p;

	size = 128 * sizeof (size_t);
	p = 0;
	m->wrapped = xmalloc(size);
	
	ptr = m->data;
	for (;;) {
		ptr = memchr(ptr, '\n', m->size);
		if (ptr == NULL)
			break;
		ptr++;
		off = ptr - m->data;
		if (m->body != -1) {
			if (off >= (size_t) m->body)
				break;
		} else {
			if (off >= m->size)
				break;
		}

		/* check if the line starts with whitespace */
		if (!isblank((int) *ptr))
			continue;

		/* save the position */
		ENSURE_SIZE(m->wrapped, size, (p + 2) * sizeof (size_t));
		m->wrapped[p] = off - 1;
		p++;
		m->wrapped[p] = 0;
	}

	if (p == 0) {
		xfree(m->wrapped);
		m->wrapped = NULL;
	}

	return (p);
}

void
set_wrapped(struct mail *m, char ch)
{
	u_int	i;

	if (m->wrapped == NULL)
		return;

	for (i = 0; m->wrapped[i] > 0; i++)
		m->data[m->wrapped[i]] = ch;
}

void
free_wrapped(struct mail *m)
{
	if (m->wrapped != NULL)	
		xfree(m->wrapped);
}
