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

#ifdef PCRE2

#include <sys/types.h>

#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>
#include <string.h>

#include "fdm.h"

int
re_compile(struct re *re, const char *s, int flags, char **cause)
{
	char		error[256];
	PCRE2_SIZE	off;
	int		errorcode;

	if (s == NULL)
		fatalx("null regexp");
	re->str = xstrdup(s);
	if (*s == '\0')
		return (0);
	re->flags = flags;

	flags = PCRE2_MULTILINE;
	if (re->flags & RE_IGNCASE)
		flags |= PCRE2_CASELESS;

	if ((re->pcre2 = pcre2_compile(s, PCRE2_ZERO_TERMINATED, flags, &errorcode, &off, NULL)) == NULL) {
		pcre2_get_error_message(errorcode, error, sizeof(error));
		*cause = xstrdup(error);
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
	int	res;
	pcre2_match_data *pmd;
	PCRE2_SIZE *ovector;
	u_int	i, j;

	if (len > INT_MAX)
		fatalx("buffer too big");

	if (rml != NULL)
		memset(rml, 0, sizeof *rml);

	/* If the regexp is empty, just check whether the buffer is empty. */
	if (*re->str == '\0') {
		if (len == 0)
			return (1);
		return (0);
	}

	pmd = pcre2_match_data_create_from_pattern(re->pcre2, NULL);
	res = pcre2_match(re->pcre2, buf, len, 0, 0, pmd, NULL);
	if (res < 0 && res != PCRE2_ERROR_NOMATCH) {
		xasprintf(cause, "%s: regexec failed", re->str);
		pcre2_match_data_free(pmd);
		return (-1);
	}

	if (rml != NULL) {
		ovector = pcre2_get_ovector_pointer(pmd);
		for (i = 0; i < res; i++) {
			j = i * 2;
			if (ovector[j + 1] <= ovector[j])
				break;
			rml->list[i].valid = 1;
			rml->list[i].so = ovector[j];
			rml->list[i].eo = ovector[j + 1];
		}
		rml->valid = 1;
	}

	return (res != PCRE2_ERROR_NOMATCH);
}

void
re_free(struct re *re)
{
	xfree(re->str);
	pcre2_code_free(re->pcre2);
}

#endif /* PCRE2 */
