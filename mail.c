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

#include <ctype.h>
#include <fnmatch.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fdm.h"

void	mail_free(struct mail *);

int
mail_open(struct mail *m, size_t size)
{
	m->size = size;
	m->space = m->size;
	m->body = 0;

	if ((m->base = shm_create(&m->shm, m->size)) == NULL)
		return (1);
 	SHM_REGISTER(&m->shm);

	m->off = 0;
	m->data = m->base + m->off;

	strb_create(&m->tags);
	ARRAY_INIT(&m->wrapped);
	m->wrapchar = '\0';
	m->attach = NULL;
	m->attach_built = 0;

	return (0);
}

void
mail_send(struct mail *m, struct msg *msg)
{
	struct mail	*mm = &msg->data.mail;

	memcpy(mm, m, sizeof *mm);
	ARRAY_INIT(&mm->wrapped);
	mm->wrapchar = '\0';
	mm->attach = NULL;
}

int
mail_receive(struct mail *m, struct msg *msg, int destroy)
{
	struct mail	*mm = &msg->data.mail;

	mm->idx = m->idx;

	mm->tags = m->tags;
	m->tags = NULL;
	mm->attach = m->attach;
	m->attach = NULL;

	mm->auxfree = m->auxfree;
	m->auxfree = NULL;
	mm->auxdata = m->auxdata;
	m->auxdata = NULL;

	if (destroy)
		mail_destroy(m);
	else
		mail_close(m);

	memcpy(m, mm, sizeof *m);
	if ((m->base = shm_reopen(&m->shm)) == NULL)
		return (1);
 	SHM_REGISTER(&m->shm);

	m->data = m->base + m->off;
	ARRAY_INIT(&m->wrapped);
	m->wrapchar = '\0';

	return (0);
}

void
mail_free(struct mail *m)
{
	if (m->attach != NULL)
		attach_free(m->attach);
	if (m->tags != NULL)
		strb_destroy(&m->tags);
	ARRAY_FREE(&m->wrapped);
	m->wrapchar = '\0';

	if (m->auxfree != NULL && m->auxdata != NULL)
		m->auxfree(m->auxdata);
}

void
mail_close(struct mail *m)
{
	mail_free(m);
	if (m->base != NULL) {
		SHM_DEREGISTER(&m->shm);
		shm_close(&m->shm);
	}
}

void
mail_destroy(struct mail *m)
{
	mail_free(m);
	if (m->base != NULL) {
		SHM_DEREGISTER(&m->shm);
		shm_destroy(&m->shm);
	}
}

int
mail_resize(struct mail *m, size_t size)
{
	if (SIZE_MAX - m->off < size)
		fatalx("size too large");
	while (m->space <= (m->off + size)) {
		if ((m->base = shm_resize(&m->shm, 2, m->space)) == NULL)
			return (1);
		m->space *= 2;
	}
	m->data = m->base + m->off;
	return (0);
}

/* Initialise for iterating over lines. */
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

/* Move to next line. */
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

/* Remove specified header. */
int
remove_header(struct mail *m, const char *hdr)
{
	char	*ptr;
	size_t	 len;

	if ((ptr = find_header(m, hdr, &len, 0)) == NULL)
		return (-1);

	/* Include the \n. */
	len++;

	/* Remove the header. */
	memmove(ptr, ptr + len, m->size - len - (ptr - m->data));
	m->size -= len;
	m->body -= len;

	return (0);
}

/* Insert header, before specified header if not NULL, otherwise at end. */
int printflike3
insert_header(struct mail *m, const char *before, const char *fmt, ...)
{
	va_list		 ap;
	char		*hdr, *ptr;
	size_t		 hdrlen, len, off, newlines;

	newlines = 1;
	if (before != NULL) {
		/* Insert before header. */
		ptr = find_header(m, before, &len, 0);
		if (ptr == NULL)
			return (-1);
		off = ptr - m->data;
	} else {
		/* Insert at the end. */
		if (m->body == 0 || m->body == 1) {
			/*
			 * Creating the headers section. Insert at the start,
			 * and add an extra newline.
			 */
			off = 0;
			newlines++;
		} else {
			/* Insert before the start of the body. */
			off = m->body - 1;
		}
	}

	/* Create the header. */
	va_start(ap, fmt);
	hdrlen = xvasprintf(&hdr, fmt, ap);
	va_end(ap);

	/* Include the newlines. */
	hdrlen += newlines;

	/* Make space for the header. */
	if (mail_resize(m, m->size + hdrlen) != 0) {
		xfree(hdr);
		return (-1);
	}
	ptr = m->data + off;
	memmove(ptr + hdrlen, ptr, m->size - off);

	/* Copy the header. */
	memcpy(ptr, hdr, hdrlen - newlines);
	memset(ptr + hdrlen - newlines, '\n', newlines);
	m->size += hdrlen;
	m->body += hdrlen;

	xfree(hdr);
	return (0);
}

/*
 * Find a header. If value is set, only the header value is returned, with EOL
 * stripped
 */
char *
find_header(struct mail *m, const char *hdr, size_t *len, int value)
{
	char	*ptr;
	size_t	 hdrlen;

	hdrlen = strlen(hdr) + 1; /* include : */
	if (m->body < hdrlen || m->size < hdrlen)
		return (NULL);

	line_init(m, &ptr, len);
	while (ptr != NULL) {
		if (ptr >= m->data + m->body)
			return (NULL);
		if (*len >= hdrlen && ptr[hdrlen - 1] == ':') {
			if (strncasecmp(ptr, hdr, hdrlen - 1) == 0)
				break;
		}
		line_next(m, &ptr, len);
	}
	if (ptr == NULL)
		return (NULL);

	/* If the entire header is wanted, return it. */
	if (!value)
		return (ptr);

	/* Otherwise skip the header and following spaces. */
	ptr += hdrlen;
	*len -= hdrlen;
	while (*len > 0 && isspace((u_char) *ptr)) {
		ptr++;
		(*len)--;
	}

	/* And trim newlines. */
	while (*len > 0 && ptr[*len - 1] == '\n')
		(*len)--;

	if (len == 0)
		return (NULL);
	return (ptr);
}

/*
 * Find offset of body. The body is the offset of the first octet after the
 * separator (\n\n), or zero.
 */
size_t
find_body(struct mail *m)
{
	size_t	 len;
	char	*ptr;

	line_init(m, &ptr, &len);
	while (ptr != NULL) {
		if (len == 1 && *ptr == '\n') {
			line_next(m, &ptr, &len);
			/* If no next line, body is end of mail. */
			if (ptr == NULL)
				return (m->size - 1);
			/* Otherwise, body is start of line after separator. */
			return (ptr - m->data);
		}
		line_next(m, &ptr, &len);
	}
	return (0);
}

/* Count mail lines. */
void
count_lines(struct mail *m, u_int *total, u_int *body)
{
	size_t	 len;
	char	*ptr;
	int	 flag;

	flag = 0;
	*total = *body = 0;

	line_init(m, &ptr, &len);
	while (ptr != NULL) {
		if (flag)
			(*body)++;
		if (len == 1 && *ptr == '\n')
			flag = 1;
		(*total)++;
		line_next(m, &ptr, &len);
	}
}

/* Append line to mail. Used during fetching. */
int
append_line(struct mail *m, char *line)
{
	size_t	size;

	size = strlen(line);
	if (mail_resize(m, m->size + size + 1) != 0)
		return (-1);
	if (size > 0)
		memcpy(m->data + m->size, line, size);
	m->data[m->size + size] = '\n';
	m->size += size + 1;
	return (0);
}

/* Fill array of users from headers. */
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
		hdr = ARRAY_ITEM(conf.headers, i);
		if (*hdr == '\0')
			continue;

		hdr = find_header(m, hdr, &len, 1);
		if (hdr == NULL || len == 0)
			continue;

		while (len > 0) {
			ptr = find_address(hdr, len, &alen);
			if (ptr == NULL)
				break;

			dptr = ((char *) memchr(ptr, '@', alen)) + 1;
			for (j = 0; j < ARRAY_LENGTH(conf.domains); j++) {
				dom = ARRAY_ITEM(conf.domains, j);
				if (fnmatch(dom, dptr, FNM_CASEFOLD) != 0)
					continue;

				*--dptr = '\0';
				pw = getpwnam(ptr);
				if (pw != NULL)
					ARRAY_ADD(users, pw->pw_uid);
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
	return (weed_users(users));
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
			if (*alen == 0 || memchr(ptr, '@', *alen) == NULL)
				break;
			if (ptr[0] == '@' || ptr[*alen - 1] == '@')
				break;
			return (ptr);
		}
	}

	/* No address found. try the whole header. */
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

	if (m->data == NULL || m->body == 0 || m->size < 5)
		return;
	if (strncmp(m->data, "From ", 5) != 0)
		return;

	line_init(m, &ptr, &len);
	m->size -= len;
	m->off += len;
	m->data = m->base + m->off;
	m->body -= len;
}

char *
make_from(struct mail *m)
{
	time_t	 t;
	char	*s, *from = NULL;
	size_t	 fromlen = 0;

	from = find_header(m, "from", &fromlen, 1);
	if (from != NULL && fromlen > 0)
		from = find_address(from, fromlen, &fromlen);
 	if (fromlen > INT_MAX)
		from = NULL;
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
	size_t	 	 end, off;
	u_int		 n;

	if (!ARRAY_EMPTY(&m->wrapped))
		fatalx("already wrapped");

	ARRAY_INIT(&m->wrapped);
	m->wrapchar = '\0';

	end = m->body;
	ptr = m->data;

	n = 0;
	for (;;) {
		ptr = memchr(ptr, '\n', m->size - (ptr - m->data));
		if (ptr == NULL)
			break;
		ptr++;
		off = ptr - m->data;
		if (off >= end)
			break;

		/* Check if the line starts with whitespace. */
		if (!isblank((u_char) *ptr))
			continue;

		/* Save the position. */
		ARRAY_ADD(&m->wrapped, off - 1);
		n++;
	}

	return (n);
}

void
set_wrapped(struct mail *m, char ch)
{
	u_int	i;

	if (m->wrapchar == ch)
		return;
	m->wrapchar = ch;

	for (i = 0; i < ARRAY_LENGTH(&m->wrapped); i++)
		m->data[ARRAY_ITEM(&m->wrapped, i)] = ch;
}
