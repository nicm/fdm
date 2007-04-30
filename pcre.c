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

#include <pcre.h>
#include <string.h>

#include "fdm.h"

#ifdef PCRE

int
re_compile(struct re *re, char *s, int flags, char **cause)
{
	const char	*error;
	int		 off;

	if (s == NULL)
		fatalx("re_compile: null regexp");
	re->str = xstrdup(s);
	if (*s == '\0')
		return (0);
	re->flags = flags;

	flags = PCRE_EXTENDED|PCRE_MULTILINE;
	if (re->flags & RE_IGNCASE)
		flags |= PCRE_CASELESS;

	if ((re->pcre = pcre_compile(s, flags, &error, &off, NULL)) == NULL) {
		*cause = xstrdup(error);
		return (1);
	}

	return (0);
}

int
re_string(struct re *re, char *s, struct rmlist *rml, char **cause)
{
	return (re_block(re, s, strlen(s), rml, cause));
}

int
re_block(struct re *re, void *buf, size_t len, struct rmlist *rml, char **cause)
{
	int		res, pm[NPMATCH];
	u_int		i, j;

	if (re->flags & RE_NOSUBST) {
		if (rml != NULL)
			fatalx("re_block: nosub re but rml != NULL");
	} else {
		if (rml == NULL)
			fatalx("re_block: !nosub re but rml == NULL");
	}
	if (len > INT_MAX)
		fatalx("re_block: len too big");

	if (rml != NULL)
		memset(rml, 0, sizeof *rml);

	/* If the regexp is empty, just check whether the buffer is empty. */
	if (*re->str == '\0') {
		if (len == 0)
			return (1);
		return (0);
	}

	res = pcre_exec(re->pcre, NULL, buf, len, 0, 0, pm, NPMATCH * 3);
	if (res < 0 && res != PCRE_ERROR_NOMATCH) {
		xasprintf(cause, "%s: regexec failed", re->str);
		return (-1);
	}

	if (rml != NULL) {
		for (i = 0; i < NPMATCH; i++) {
			j = i * 2;
			if (pm[j + 1] <= pm[j])
				break;
			rml->list[i].valid = 1;
			rml->list[i].so = pm[j];
			rml->list[i].eo = pm[j + 1];
		}
		rml->valid = 1;
	}

	return (res != PCRE_ERROR_NOMATCH);
}

void
re_free(struct re *re)
{
	xfree(re->str);
	pcre_free(re->pcre);
}

#endif
