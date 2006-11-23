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
#include <fnmatch.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fdm.h"

void
init_mail(struct mail *m, size_t size)
{
	memset(m, 0, sizeof m);

	m->size = size;
	m->space = m->size;
	m->body = -1;

	m->base = shm_malloc(&m->shm, m->size);

	m->off = 0;
	m->data = m->base + m->off;
}

void
copy_mail(struct mail *src, struct mail *dst)
{
	memcpy(dst, src, sizeof *dst);
	ARRAY_INIT(&dst->tags);
	dst->wrapped = NULL;
}

void
free_mail(struct mail *m, int final)
{
	if (!ARRAY_EMPTY(&m->tags))
		ARRAY_FREE(&m->tags);
	free_wrapped(m);
	if (m->base != NULL) {
		if (final)
			shm_destroy(&m->shm);
		else
			shm_free(&m->shm);
	}
}
void
resize_mail(struct mail *m, size_t size)
{
	if (SIZE_MAX - m->off < m->size)
		fatalx("resize_mail: SIZE_MAX - m->off < m->size");
	while (m->space <= (m->off + size)) {
		m->base = shm_realloc(&m->shm, 2, m->space);
		m->space *= 2;
	}
	m->data = m->base + m->off;
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
line_init(struct mail *m, char **line, size_t *len)
{
	char	*ptr;

	*line = m->data;

	ptr = memchr(m->data, '\n', m->size);
	if (ptr == NULL)
		*len = m->size;
	else
		*len = (ptr - *line) + 1;
}

void
line_next(struct mail *m, char **line, size_t *len)
{
	char	*ptr;

	*line += *len;
	if (*line == m->data + m->size) {
		*line = NULL;
		return;
	}

	ptr = memchr(*line, '\n', (m->data + m->size) - *line);
	if (ptr == NULL)
		*len = (m->data + m->size) - *line;
	else
		*len = (ptr - *line) + 1;
}

char *
find_header(struct mail *m, const char *hdr, size_t *len)
{
	char	*ptr, *end, *out;

	*len = strlen(hdr);

	end = m->data + (m->body == -1 ? m->size : (size_t) m->body);
	ptr = m->data;
	do {
		ptr = memchr(ptr, '\n', end - ptr);
		if (ptr == NULL)
			return (NULL);
		ptr++;
		if (*len > (size_t) (end - ptr))
			return (NULL);
	} while (strncasecmp(ptr, hdr, *len) != 0);

	out = ptr + *len;
	ptr = memchr(out, '\n', end - out);
	if (ptr == NULL)
		*len = end - out;
	else
		*len = (ptr - out) + 1;

	return (out);
}

struct users *
find_users(struct mail *m)
{
	struct passwd	*pw;
	struct users	*users;
	u_int	 	 i, j;
	char		*hdr, *ptr, *dptr, *dom;
	size_t	 	 len, alen;

	users = xmalloc(sizeof *users);
	ARRAY_INIT(users);

	for (i = 0; i < ARRAY_LENGTH(conf.headers); i++) {
		if (*ARRAY_ITEM(conf.headers, i, char *) == '\0')
			continue;

		xasprintf(&ptr, "%s: ", ARRAY_ITEM(conf.headers, i, char *));
		hdr = find_header(m, ptr, &len);
		xfree(ptr);

		if (hdr == NULL || len < 1)
			continue;
		len--;	/* lose \n */
		while (isspace((int) *hdr)) {
			hdr++;
			len--;
		}
		if (*hdr == '\0')
			continue;

		while (len > 0) {
			ptr = find_address(hdr, len, &alen);
			if (ptr == NULL)
				break;

			dptr = ((char *) memchr(ptr, '@', alen)) + 1;
			for (j = 0; j < ARRAY_LENGTH(conf.domains); j++) {
				dom = ARRAY_ITEM(conf.domains, j, char *);
				if (fnmatch(dom, dptr, FNM_CASEFOLD) != 0)
					continue;
				*--dptr = '\0';
				pw = getpwnam(ptr);
				if (pw != NULL)
					ARRAY_ADD(users, pw->pw_uid, uid_t);
				endpwent();
				*dptr++ = '@';
				break;
			}

			len -= (ptr - hdr) + alen;
			hdr = ptr + alen;
		}
	}

	if (ARRAY_EMPTY(users)) {
		ARRAY_FREE(users);
		xfree(users);
		return (NULL);
	}
	return (users);
}

char *
find_address(char *hdr, size_t len, size_t *alen)
{
	char	*ptr;
	size_t	 off, pos;

	for (off = 0; off < len; off++) {
		switch (hdr[off]) {
		case '"':
			off++;
			while (off < len && hdr[off] != '"')
				off++;
			if (off < len)
				off++;
			break;
		case '<':
			off++;
			ptr = memchr(hdr + off, '>', len - off);
			if (ptr == NULL)
				break;
			*alen = ptr - (hdr + off);
			for (pos = 0; pos < *alen; pos++) {
				if (!isaddr(hdr[off + pos]))
					break;
			}
			if (pos != *alen)
				break;
			ptr = hdr + off;
			if (*alen == 0 || memchr(ptr + off, '@', *alen) == NULL)
				break;
			if (ptr[0] == '@' || ptr[*alen - 1] == '@')
				break;
			return (ptr);
		}
	}

	/* no address found */
	*alen = 0;
	for (*alen = 0; *alen < len; (*alen)++) {
		if (!isaddr(hdr[*alen]))
			break;
	}
	if (*alen == 0 || memchr(hdr + off, '@', *alen) == NULL)
		return (NULL);
	if (hdr[off] == '@' || hdr[*alen - 1] == '@')
		return (NULL);
	return (hdr);
}

void
trim_from(struct mail *m)
{
	char	*ptr;
	size_t	 len;

	if (m->data == NULL || m->size < 5 || strncmp(m->data, "From ", 5) != 0)
		return;

	ptr = memchr(m->data, '\n', m->size);
	if (ptr == NULL)
		ptr = m->data + m->size;
	else
		ptr++;
	len = ptr - m->data;

	m->size -= len;
	m->off += len;
	m->data = m->base + m->off;
	if (m->body != -1)
		m->body -= len;
}

char *
make_from(struct mail *m)
{
	time_t	 t;
	char	*s, *from = NULL;
	size_t	 fromlen = 0;

	from = find_header(m, "From: ", &fromlen);
 	if (fromlen > INT_MAX)
		from = NULL;
	if (from != NULL && fromlen > 0)
		from = find_address(from, fromlen, &fromlen);
	if (from == NULL) {
		from = conf.info.user;
		fromlen = strlen(from);
	}

	t = time(NULL);
	xasprintf(&s, "From %.*s %.24s", (int) fromlen, from, ctime(&t));
	return (s);
}

/*
 * Sometimes mail has wrapped header lines, this undoubtedly looks neat but
 * makes them a pain to match using regexps. We build a list of the newlines
 * in all the wrapped headers in m->wrapped, and can then quickly unwrap them
 * for regexp matching and wrap them again for delivery.
 */
u_int
fill_wrapped(struct mail *m)
{
	char		*ptr;
	size_t	 	 off, end, size;
	u_int		 p;

	size = 128 * sizeof (size_t);
	p = 0;
	m->wrapped = xmalloc(size);

	end = m->body == -1 ? m->size : (size_t) m->body;
	ptr = m->data;
	for (;;) {
		ptr = memchr(ptr, '\n', m->size - (ptr - m->data));
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
		ENSURE_FOR2(m->wrapped, size, p, 2, sizeof (size_t));
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
	m->wrapped = NULL;
}
