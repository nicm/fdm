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
#include <string.h>

#include "fdm.h"

void		 attach_print(struct attach *, const char *, u_int);
char 		*attach_type(struct mail *, char *, const char *, char **);
struct attach	*attach_get(struct mail *, char **, size_t *, const char *,
		    int *);

void
attach_print(struct attach *at, const char *prefix, u_int n)
{
	u_int	i;

	if (ARRAY_EMPTY(&at->list)) {
		if (at->name == NULL) {
			log_debug("%s:%*s%u, %s: offset %zu, size %zu, "
			    "body %zu", prefix, n + 1, " ", at->idx, at->type,
			    at->data, at->size, at->body);
		} else {
			log_debug("%s:%*s%u, %s: offset %zu, size %zu, "
			    "body %zu: %s", prefix, n + 1, " ", at->idx,
			    at->type, at->data, at->size, at->body, at->name);
		}
		return;
	}

	log_debug("%s:%*s%u, %s", prefix, n  + 1, " ", at->idx, at->type);
	for (i = 0; i < ARRAY_LENGTH(&at->list); i++) {
		attach_print(ARRAY_ITEM(&at->list, i, struct attach *),
		    prefix, n + 1);
	}
}

void
attach_log(struct attach *at, const char *fmt, ...)
{
	va_list	 ap;
	char	*prefix;

	va_start(ap, fmt);
	if (vasprintf(&prefix, fmt, ap) < 0)
		fatalx("vasprintf");
	va_end(ap);

	attach_print(at, prefix, 0);

	free(prefix);
}

void
attach_free(struct attach *at)
{
	u_int	i;

	for (i = 0; i < ARRAY_LENGTH(&at->list); i++)
		attach_free(ARRAY_ITEM(&at->list, i, struct attach *));
	
	ARRAY_FREE(&at->list);
	if (at->type != NULL)
		xfree(at->type);
	if (at->name != NULL)
		xfree(at->name);
	xfree(at);
}

char *
attach_type(struct mail *m, char *hdr, const char *name, char **value)
{
	size_t	 len, llen;
	ssize_t	 namelen;
	char	*ptr, *type = NULL;

	*value = NULL;

	len = m->size - (hdr - m->data);
	if (len < 13 && strncasecmp(hdr, "content-type:", 13) != 0)
		goto error;
	len -= 13;
	hdr += 13;

	/* skip spaces */
	while (len > 0 && isspace((int) *hdr)) {	
		len--;
		hdr++;
	}
	if (len == 0)
		goto error;

	/* find end of line */
	ptr = memchr(hdr, '\n', len);
	if (ptr == NULL)
		llen = len;
	else
		llen = ptr - hdr;

	/* find type */
	ptr = memchr(hdr, ';', llen);
	if (ptr == NULL)
		ptr = hdr + llen;
	type = xmalloc(ptr - hdr + 1);
	memcpy(type, hdr, ptr - hdr);
	type[ptr - hdr] = '\0';
	len -= ptr - hdr;
	hdr = ptr;

	/* if this is now the end of the line, return the type */
	if (len == 0 || *ptr == '\n')
		return (type);
	/* skip the semicolon */
	len--;
	hdr++;

	/* now follows a set of attributes of the form name=value, seperated
	   by semicolons, possibly crossing multiple lines and possibly with
	   the value enclosed in quotes */
	namelen = strlen(name);
	for (;;) {
		/* skip spaces and newlines */
		while (len > 0 && (isspace((int) *hdr) || *hdr == '\n')) {
			hdr++;
			len--;
		}
		if (len == 0)
			goto error;

		/* find end of line */
		ptr = memchr(hdr, '\n', len);
		if (ptr == NULL)
			llen = len;
		else
			llen = ptr - hdr;

		/* find the end of the attribute name */
		ptr = memchr(hdr, '=', llen);
		if (ptr == NULL)
			break;
		if (ptr - hdr == namelen && strncmp(hdr, name, namelen) == 0) {
 			llen -= (ptr - hdr + 1);
			hdr = ptr + 1;
			
			ptr = memchr(hdr, ';', llen);
			if (ptr != NULL)
				llen = ptr - hdr;
			if (*hdr == '"') {
				if (llen < 2 || hdr[llen - 1] != '"')
					goto error;
				hdr++;
				llen -= 2;
			}

			*value = xmalloc(llen + 1);
			memcpy(*value, hdr, llen);
			(*value)[llen] = '\0';
			break;
		}

		/* skip to next semicolon */
		ptr = memchr(hdr, ';', llen);
		if (ptr == NULL)
			break;
		hdr = ptr + 1;
		len -= (ptr - hdr) + 1;
	}

	return (type);

error:
	if (type != NULL)
		xfree(type);
	if (*value != NULL) {
		xfree(*value); 
		*value = NULL;
	}
	return (NULL);
}

struct attach *
attach_build(struct mail *m)
{
	struct attach	*atr = NULL, *at;
	char		*hdr, *ptr, *b = NULL;
	size_t		 len, bl;
	int		 last;

	hdr = find_header(m, "content-type:", &len);
	if (hdr == NULL)
		return (NULL);
	hdr -= 13;

	atr = xmalloc(sizeof *atr);
	memset(atr, 0, sizeof *atr);
	ARRAY_INIT(&atr->list);

	atr->type = attach_type(m, hdr, "boundary", &b);
	if (atr->type == NULL || b == NULL)
		goto error;
	bl = strlen(b);

	/* find the first boundary */
	line_init(m, &ptr, &len);
	while (ptr != NULL) {
		if (ptr[0] == '-' && ptr[1] == '-') {
			if (len - 3 == bl && strncmp(ptr + 2, b, bl) == 0)
				break;
		}
		line_next(m, &ptr, &len);
	}
	if (ptr == NULL)
		goto error;

	/* now iterate over the rest */
	last = 0;
	while (ptr != NULL && !last) {
		at = attach_get(m, &ptr, &len, b, &last);
		if (at == NULL)
			goto error;
		at->idx = ARRAY_LENGTH(&atr->list);
		ARRAY_ADD(&atr->list, at, struct attach *);
	}
	if (ptr == NULL)
		goto error;

	xfree(b);
	return (atr);

error:
	attach_free(atr);

	if (b != NULL)
		xfree(b);
	return (NULL);
}

struct attach *
attach_get(struct mail *m, char **ptr, size_t *len, const char *b, int *last)
{
	struct attach	*atr, *at;
	char		*name = NULL, *b2 = NULL;
	size_t		 bl, bl2;
	int		 last2;

	bl = strlen(b);

	atr = xmalloc(sizeof *atr);
	memset(atr, 0, sizeof *atr);
	ARRAY_INIT(&atr->list);

	atr->data = *ptr - m->data;
	line_next(m, ptr, len);
	if (*ptr == NULL)
		goto error;

	atr->type = attach_type(m, *ptr, "name", &name);
	if (atr->type == NULL) {
		if (name != NULL)
			xfree(name);
		goto error;
	}
	atr->name = name;

	if (strncmp(atr->type, "multipart/", 10) != 0) {
		/* skip the remaining headers */
		while (*ptr != NULL && *len > 1)
			line_next(m, ptr, len);		
		if (*ptr == NULL)
			goto error;	

		atr->body = *ptr - m->data;
		for (;;) {
			line_next(m, ptr, len);
			if (*ptr == NULL)
				break;
			if (*len < 3 || (*ptr)[0] != '-' || (*ptr)[1] != '-')
				continue;

			if (*len - 5 == bl && strncmp(*ptr + 2, b, bl) == 0 &&
			    strncmp(*ptr + bl + 2, "--", 2) == 0) {
				*last = 1;
				break;
			}
			if (*len - 3 == bl && strncmp(*ptr + 2, b, bl) == 0)
				break;
		}
		if (*ptr == NULL)
			goto error;

		atr->size = *ptr - m->data - atr->data;
	} else {
		/* XXX avoid doing this twice */
		xfree(atr->type);
		atr->type = attach_type(m, *ptr, "boundary", &b2);

		bl2 = strlen(b2);

		/* find the first boundary */
		while (*ptr != NULL) {
			if ((*ptr)[0] == '-' && (*ptr)[1] == '-') {
				if (*len - 3 == bl2 && 
				    strncmp(*ptr + 2, b2, bl2) == 0)
					break;
			}
			line_next(m, ptr, len);
		}
		if (ptr == NULL)
			goto error;
		
		/* now iterate over the rest */
		last2 = 0;
		while (*ptr != NULL && !last2) {
			at = attach_get(m, ptr, len, b2, &last2);
			if (at == NULL)
				goto error;
			at->idx = ARRAY_LENGTH(&atr->list);
			ARRAY_ADD(&atr->list, at, struct attach *);
		}

		/* and skip on to the end of the multipart */
		while (*ptr != NULL) {
			if ((*ptr)[0] == '-' && (*ptr)[1] == '-') {
				if (*len - 3 == bl && 
				    strncmp(*ptr + 2, b, bl) == 0)
					break;
			}
			line_next(m, ptr, len);
		}
		if (ptr == NULL)
			goto error;

		xfree(b2);
	}
	
	return (atr);
	
error:
	if (b2 != NULL)
		xfree(b2);

	attach_free(atr);
	return (NULL);
}
