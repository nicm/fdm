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

#include <string.h>

#include "fdm.h"

int	size_match(struct match_ctx *, struct expritem *);
char   *size_desc(struct expritem *);

struct match match_size = { "size", size_match, size_desc };

int
size_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct size_data	*data = ei->data;
	struct mail		*m = mctx->mail;
	
	switch (data->cmp) {
	case CMP_LT:
		if (m->size < data->size)
			return (MATCH_TRUE);
		return (MATCH_FALSE);
	case CMP_GT:
		if (m->size > data->size)
			return (MATCH_TRUE);
		return (MATCH_FALSE);
	default:
		return (MATCH_ERROR);
	}
}

char *
size_desc(struct expritem *ei)
{
	struct size_data	*data = ei->data;
	char			*s;
	const char		*cmp;

	switch (data->cmp) {
	case CMP_LT:
		cmp = "<";
		break;
	case CMP_GT:
		cmp = ">";
		break;
	default:
		cmp = "";
		break;
	}

	xasprintf(&s, "%s %zu", cmp, data->size);
	return (s);
}
