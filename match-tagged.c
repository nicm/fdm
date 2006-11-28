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

#include <fnmatch.h>
#include <string.h>

#include "fdm.h"

int	tagged_match(struct match_ctx *, struct expritem *);
char   *tagged_desc(struct expritem *);

struct match match_tagged = { tagged_match, tagged_desc };

int
tagged_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct tagged_data	*data = ei->data;
	struct mail		*m = mctx->mail;
	u_int			 i;

	for (i = 0; i < ARRAY_LENGTH(&m->tags); i++) {
		if (tag_match(data->tag, ARRAY_ITEM(&m->tags, i, char *)))
			return (MATCH_TRUE);
	}

	return (MATCH_FALSE);
}

char *
tagged_desc(struct expritem *ei)
{
	struct tagged_data	*data = ei->data;
	char			*s;

	xasprintf(&s, "tagged %s", data->tag);
	return (s);
}
