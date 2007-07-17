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

#ifndef PCRE

#include <sys/types.h>

#include <string.h>

#include "fdm.h"

int
re_compile(struct re *re, const char *s, int flags, char **cause)
{
	int	 error;
	size_t	 len;
	char	*buf;

	if (s == NULL)
		log_fatalx("re_compile: null regexp");
	re->str = xstrdup(s);
	if (*s == '\0')
		return (0);
	re->flags = flags;

	flags = REG_EXTENDED|REG_NEWLINE;
	if (re->flags & RE_NOSUBST)
		flags |= REG_NOSUB;
	if (re->flags & RE_IGNCASE)
		flags |= REG_ICASE;

	if ((error = regcomp(&re->re, s, flags)) != 0) {
		len = regerror(error, &re->re, NULL, 0);
		buf = xmalloc(len);
		regerror(error, &re->re, buf, len);
		xasprintf(cause, "%s%s", s, buf);
		return (-1);
	}

	return (0);
}

int
re_string(struct re *re, const char *s, struct rmlist *rml, char **cause)
{
	return (re_block(re, s, strlen(s), rml, cause));
}

int
re_block(struct re *re, const void *buf, size_t len, struct rmlist *rml,
    char **cause)
{
	int		res;
	regmatch_t	pm[NPMATCH];
	u_int		i;

	if (rml != NULL)
		memset(rml, 0, sizeof *rml);

	/* If the regexp is empty, just check whether the buffer is empty. */
	if (*re->str == '\0') {
		if (len == 0)
			return (1);
		return (0);
	}

	memset(pm, 0, sizeof pm);
	pm[0].rm_so = 0;
	pm[0].rm_eo = len;
	res = regexec(&re->re, buf, NPMATCH, pm, REG_STARTEND);
	if (res != 0 && res != REG_NOMATCH) {
		xasprintf(cause, "%s: regexec failed", re->str);
		return (-1);
	}

	if (rml != NULL) {
		for (i = 0; i < NPMATCH; i++) {
			if (pm[i].rm_eo <= pm[i].rm_so)
				break;
			rml->list[i].valid = 1;
			rml->list[i].so = pm[i].rm_so;
			rml->list[i].eo = pm[i].rm_eo;
		}
		rml->valid = 1;
	}

	return (res == 0);
}

void
re_free(struct re *re)
{
	xfree(re->str);
	regfree(&re->re);
}

#endif /* !PCRE */
