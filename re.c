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

#include "fdm.h"

int
re_compile(struct re *re, char *s, int flags, char **cause)
{
	int	 error;
	size_t	 len;
	char	*buf;

	if (s == NULL || *s == '\0') {
		*cause = xstrdup("invalid regexp");
		return (1);
	}
	re->str = s;

	if ((error = regcomp(&re->re, s, flags)) != 0) {
		len = regerror(error, &re->re, NULL, 0);
		buf = xmalloc(len);
		regerror(error, &re->re, buf, len);
		xasprintf(cause, "%s: %s", s, buf);
		return (1);
	}

	return (0);
}

int
re_execute(struct re *re, char *s, int npm, regmatch_t *pm, int flags,
    char **cause)
{
	int	res;

	res = regexec(&re->re, s, npm, pm, flags);
	if (res != 0 && res != REG_NOMATCH) {
		xasprintf(cause, "%s: regexec failed", re->str);
		return (-1);
	}

	if (res == 0)
		return (1);
	return (0);
}

int
re_simple(struct re *re, char *s, char **cause)
{
	return (re_execute(re, s, 0, NULL, 0, cause));
}
