/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicholas.marriott@gmail.com>
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
	m->size = 0;
	m->space = IO_ROUND(size);
	m->body = 0;

	if ((m->base = shm_create(&m->shm, m->space)) == NULL)
		return (-1);
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
		return (-1);
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
			return (-1);
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
	size_t		 hdrlen, len, off;
	u_int		 newlines;

	newlines = 1;
	if (before != NULL) {
		/* Insert before header. */
		ptr = find_header(m, before, &len, 0);
		if (ptr == NULL) {
			log_debug3("header \"%s\" not found, adding to the top",
			    before);
			off = 0;
		} else
			off = ptr - m->data;
	} else {
		/* Insert at the end. */
		if (m->body == 0) {
			/*
			 * Creating the headers section. Insert at the start,
			 * and add an extra newline.
			 */
			off = 0;
			newlines++;
		} else {
			/*
			 * Body points just after the blank line. Insert before
			 * the blank line.
			 */
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

/* Match a header. Same as find_header but uses fnmatch. */
char *
match_header(struct mail *m, const char *patt, size_t *len, int value)
{
	char	*ptr, *last, *hdr;
	size_t	 hdrlen;

	line_init(m, &ptr, len);
	while (ptr != NULL) {
		if (ptr >= m->data + m->body)
			return (NULL);

		if ((last = memchr(ptr, ':', *len)) != NULL) {
			hdrlen = last - ptr;
			hdr = xmalloc(hdrlen + 1);
			strlcpy(hdr, ptr, hdrlen + 1);

			if (fnmatch(patt, hdr, FNM_CASEFOLD) == 0)
				break;

			xfree(hdr);
		}

		line_next(m, &ptr, len);
	}
	if (ptr == NULL)
		return (NULL);
	xfree(hdr);

	/* If the entire header is wanted, return it. */
	if (!value)
		return (ptr);

	/* Include the : in the length. */
	hdrlen++;

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
				return (m->size);
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
append_line(struct mail *m, const char *line, size_t size)
{
	if (mail_resize(m, m->size + size + 1) != 0)
		return (-1);
	if (size > 0)
		memcpy(m->data + m->size, line, size);
	m->data[m->size + size] = '\n';
	m->size += size + 1;
	return (0);
}

char *
find_address(char *buf, size_t len, size_t *alen)
{
	char	*ptr, *hdr, *first, *last;

	/*
	 * RFC2822 email addresses are stupidly complicated, so we just do a
	 * naive match which is good enough for 99% of addresses used now. This
	 * code is pretty inefficient.
	 */

	/* Duplicate the header as a string to work on it. */
	if (len == 0)
		return (NULL);
	hdr = xmalloc(len + 1);
	strlcpy(hdr, buf, len + 1);

	/* First, replace any sections in "s with spaces. */
	ptr = hdr;
	while (*ptr != '\0') {
		if (*ptr == '"') {
			ptr++;
			while (*ptr != '"' && *ptr != '\0')
				*ptr++ = ' ';
			if (*ptr == '\0')
				break;
		}
		ptr++;
	}

	/*
	 * Now, look for sections matching:
	 *	[< ][A-Za-z0-9._%+-]+@[A-Za-z0-9.\[\]-]+[> ,;].
	 */
#define isfirst(c) ((c) == '<' || (c) == ' ')
#define islast(c) ((c) == '>' || (c) == ' ' || (c) == ',' || (c) == ';')
#define isuser(c) (isalnum(c) || \
	(c) == '.' || (c) == '_' || (c) == '%' || (c) == '+' || (c) == '-')
#define isdomain(c) (isalnum(c) || \
	(c) == '.' || (c) == '-' || (c) == '[' || (c) == ']')
	ptr = hdr + 1;
	for (;;) {
		/* Find an @. */
		if ((ptr = strchr(ptr, '@')) == NULL)
			break;

		/* Find the end. */
		last = ptr + 1;
		while (*last != '\0' && isdomain((u_char) *last))
			last++;
		if (*last != '\0' && !islast((u_char) *last)) {
			ptr = last + 1;
			continue;
		}

		/* Find the start. */
		first = ptr - 1;
		while (first != hdr && isuser((u_char) *first))
			first--;
		if (first != hdr && !isfirst((u_char) *first)) {
			ptr = last + 1;
			continue;
		}

		/* If the last is > the first must be < and vice versa. */
		if (*last == '>' && *first != '<') {
			ptr = last + 1;
			continue;
		}
		if (*first == '<' && *last != '>') {
			ptr = last + 1;
			continue;
		}

		/* If not right at the start, strip first character. */
		if (first != hdr)
			first++;

		/* Free header copy. */
		xfree(hdr);

		/* Have last and first, return the address. */
		*alen = last - first;
		return (buf + (first - hdr));
	}

	xfree(hdr);
	return (NULL);
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
make_from(struct mail *m, char *user)
{
	time_t		 t;
	char		*s, *from = NULL;
	const char	*mfrom;
	size_t		 fromlen = 0;

	mfrom = find_tag(m->tags, "mbox_from");
	if (mfrom != NULL) {
		xasprintf(&s, "%s", mfrom);
		return (s);
	}
	from = find_header(m, "from", &fromlen, 1);
	if (from != NULL && fromlen > 0)
		from = find_address(from, fromlen, &fromlen);
	if (fromlen > INT_MAX)
		from = NULL;
	if (from == NULL) {
		from = user;
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
	size_t		 end, off;
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
