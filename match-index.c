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

#include <regex.h>
#include <string.h>

#include "fdm.h"

int	index_match(struct match_ctx *, struct expritem *);
char   *index_desc(struct expritem *);

struct match match_index = { "index", index_match, index_desc };

int
index_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct index_data	*data;
	int			 res;
	char			*s;
	size_t	 		 len;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
        regmatch_t		*pmatch = mctx->regexp_pmatch;

	data = ei->data;

	if (mctx->regexp_valid != 1) {
		log_warnx("%s: index match before any regexps", a->name);
		return (MATCH_ERROR);
	}

	log_debug2("%s: index %u is from %lld to %lld", a->name, data->index,
	    (long long) pmatch[data->index].rm_so, 
	    (long long) pmatch[data->index].rm_eo);
	if (pmatch[data->index].rm_so >= pmatch[data->index].rm_eo)
		return (MATCH_FALSE);
	len = pmatch[data->index].rm_eo - pmatch[data->index].rm_so;

	s = xmalloc(len + 1);
	memcpy(s, m->data + pmatch[data->index].rm_so, len);
	s[len] = '\0';
	
	res = regexec(&data->re, s, 0, NULL, 0);
	if (res != 0 && res != REG_NOMATCH) {
		log_warnx("%s: %s: regexec failed", a->name, data->re_s);
		xfree(s);
		return (MATCH_ERROR);
	}

	xfree(s);
	return (res == 0 ? MATCH_TRUE : MATCH_FALSE);
}

char *
index_desc(struct expritem *ei)
{
	struct index_data	*data;
	char			*s;

	data = ei->data;

	xasprintf(&s, "\\%u to \"%s\"", data->index, data->re_s);
	return (s);
}
