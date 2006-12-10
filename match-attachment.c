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

int	attachment_match(struct match_ctx *, struct expritem *);
char   *attachment_desc(struct expritem *);

struct match match_attachment = { attachment_match, attachment_desc };

int
attachment_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct attachment_data	*data = ei->data;
	struct mail		*m = mctx->mail;

	return (MATCH_ERROR);
}

char *
attachment_desc(struct expritem *ei)
{
	struct attachment_data	*data = ei->data;
	char			*s;
	const char 		*cmp = "";

	if (data->cmp == CMP_LT)
		cmp = "<";
	else if (data->cmp == CMP_GT)
		cmp = ">";
	else if (data->cmp == CMP_EQ)
		cmp = "==";
	else if (data->cmp == CMP_NE)
		cmp = "!=";

	switch (data->op) {
	case ATTACHOP_COUNT:
		xasprintf(&s, "attachment count %s %lld", cmp,
		    data->value.number);
		return (s);
	case ATTACHOP_TOTALSIZE:
		xasprintf(&s, "attachment total-size %s %lld", cmp,
		    data->value.number);
		return (s);
	case ATTACHOP_ANYSIZE:
		xasprintf(&s, "attachment any-size %s %lld", cmp,
		    data->value.number);
		return (s);
	case ATTACHOP_ANYTYPE:
		xasprintf(&s, "attachment any-type \"%s\"", data->value.string);
		return (s);
	case ATTACHOP_ANYNAME:
		xasprintf(&s, "attachment any-name \"%s\"", data->value.string);
		return (s);
	default:
		return (xstrdup(""));
	}
}
