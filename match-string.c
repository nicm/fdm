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
#include "match.h"

int	match_string_match(struct match_ctx *, struct expritem *);
void	match_string_desc(struct expritem *, char *, size_t);

struct match match_string = {
	match_string_match,
	match_string_desc
};

int
match_string_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct match_string_data	*data = ei->data;
	struct account			*a = mctx->account;
	struct mail			*m = mctx->mail;
	int				 res;
	char				*s, *cause;

	s = replacestr(&data->str, m->tags, m, &m->rml);
	log_debug2("%s: matching \"%s\" to \"%s\"", a->name, s, data->re.str);

	res = re_simple(&data->re, s, &cause);
	xfree(s);

	if (res == -1) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (MATCH_ERROR);
	}

	if (res == 0)
		return (MATCH_FALSE);
	return (MATCH_TRUE);
}

void
match_string_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_string_data	*data = ei->data;

	xsnprintf(buf, len,
	    "string \"%s\" to \"%s\"", data->str.str, data->re.str);
}
