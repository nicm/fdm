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

int	match_unmatched_match(struct mail_ctx *, struct expritem *);
void	match_unmatched_desc(struct expritem *, char *, size_t);

struct match match_unmatched = { 
	"unmatched",
	match_unmatched_match,
	match_unmatched_desc
};

int
match_unmatched_match(struct mail_ctx *mctx, unused struct expritem *ei)
{
	if (mctx->matched)
		return (MATCH_FALSE);
	return (MATCH_TRUE);
}

void
match_unmatched_desc(unused struct expritem *ei, char *buf, size_t len)
{
	strlcpy(buf, "unmatched", len);
}
