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
#include "match.h"

int	match_size_match(struct match_ctx *, struct expritem *);
void	match_size_desc(struct expritem *, char *, size_t);

struct match match_size = {
	match_size_match,
	match_size_desc
};

int
match_size_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct match_size_data	*data = ei->data;
	struct mail		*m = mctx->mail;

	if (data->cmp == CMP_LT && m->size < data->size)
		return (MATCH_TRUE);
	else if (data->cmp == CMP_GT && m->size > data->size)
		return (MATCH_TRUE);
	return (MATCH_FALSE);
}

void
match_size_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_size_data	*data = ei->data;
	const char		*cmp = "";

	if (data->cmp == CMP_LT)
		cmp = "<";
	else if (data->cmp == CMP_GT)
		cmp = ">";
	xsnprintf(buf, len, "size %s %zu", cmp, data->size);
}
