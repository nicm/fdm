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
#include <sys/file.h>
#include <sys/stat.h>

#include <ctype.h>
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
	}

	fd = open(path, flags, mode);
	
	if (fd != -1 && locks & LOCK_FLOCK) {
		if (flock(fd, LOCK_EX|LOCK_NB) != 0) {
			if (errno == EWOULDBLOCK)
				errno = EAGAIN;
			goto error;
		}
	}

	if (fd != -1 && locks & LOCK_FCNTL) {
		memset(&fl, 0, sizeof fl);
		fl.l_start = 0;
		fl.l_len = 0;
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		if (fcntl(fd, F_SETLK, &fl) == -1) {
			/* fcntl already returns EAGAIN if needed */
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
		unlink(lock);
		xfree(lock);
	}
	errno = error;
	return (-1);
}

void
closelock(int fd, char *path, u_int locks)
{
	char	*lock;

	if (locks & LOCK_DOTLOCK) {
		xasprintf(&lock, "%s.lock", path);
		unlink(lock);
		xfree(lock);
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
	size_t	 end, off, fromlen = 0, datelen = 0;
	time_t	 t;
	char	*from = NULL, *date = NULL, *ptr;

	if (m->from != NULL)
		return;

	/* find the from and date headers */
	end = m->body == -1 ? m->size : (size_t) m->body;	
	ptr = m->data;
	while (from == NULL || date == NULL) {
		ptr = memchr(ptr, '\n', m->size);
		if (ptr == NULL)
			break;
		ptr++;
		off = ptr - m->data;
		if (off >= end)
			break;

		if (m->size - off > 6 && strncmp(ptr, "From: ", 6) == 0)
			from = ptr + 6;
		else if (m->size - off > 6 && strncmp(ptr, "Date: ", 6) == 0)
			date = ptr + 6;
	}
	    
	if (from != NULL) {
		ptr = memchr(from, '<', end - (from - m->data));
		if (ptr != NULL) {
			from = ptr + 1;
			ptr = memchr(from, '>', end - (from - m->data));
			if (ptr != NULL)
 				fromlen = ptr - from;
			else
				from = NULL;
		} else {
			/* can't find a <...>, so just use the first word */
			ptr = from;
			while (*ptr != '\n' && !isblank((int) *ptr))
				ptr++;
			fromlen = ptr - from;
		}
	}
	if (from == NULL) {
		from = conf.user;
		fromlen = strlen(from);
	}

	if (date != NULL) {
		while (isblank((int) *date))
			date++;
		ptr = memchr(date, '\n', end - (date - m->data));
		if (ptr != NULL)
			datelen = ptr - date;
		else
			date = NULL;
	} 
	if (date == NULL) {
		t = time(NULL);
		date = ctime(&t);
		datelen = strlen(date);
	}

	xasprintf(&ptr, "From %%.%ds %%.%ds\n", fromlen, datelen);
	xasprintf(&m->from, ptr, from, date);
	free(ptr);
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
	size_t	 	 off, end;
	u_int		 size, p;

	size = 128 * sizeof (size_t);
	p = 0;
	m->wrapped = xmalloc(size);

	end = m->body == -1 ? m->size : (size_t) m->body;	
	ptr = m->data;
	for (;;) {
		ptr = memchr(ptr, '\n', m->size);
		if (ptr == NULL)
			break;
		ptr++;
		off = ptr - m->data;
		if (off >= end)
			break;

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
