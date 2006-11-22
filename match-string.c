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

int	string_match(struct match_ctx *, struct expritem *);
char   *string_desc(struct expritem *);

struct match match_string = { "string", string_match, string_desc };

int
string_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct string_data	*data;
	int			 res;
	char			*s;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
        regmatch_t		*pmatch = mctx->pmatch;

	data = ei->data;

	if (!mctx->pmatch_valid) {
		log_warnx("%s: string match but no regexp match data available",
		    a->name);
		return (MATCH_FALSE);
	}

	s = replacepmatch(data->s, m, pmatch);
	log_debug2("%s: matching \"%s\" to \"%s\"", a->name, s, data->re_s);

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
string_desc(struct expritem *ei)
{
	struct string_data	*data;
	char			*s;

	data = ei->data;

	xasprintf(&s, "\"%s\" to \"%s\"", data->s, data->re_s);
	return (s);
}
