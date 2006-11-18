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

int	tag_match(struct account *, struct mail *, struct expritem *);
char   *tag_desc(struct expritem *);

struct match match_tag = { "tag", tag_match, tag_desc };

int
tag_match(unused struct account *a, struct mail *m, struct expritem *ei)
{
	struct tag_data	*data;

	data = ei->data;

	if (data->tag == NULL)
		return (0);

	return (strcmp(data->tag, m->tag) == 0);
}

char *
tag_desc(struct expritem *ei)
{
	struct tag_data	*data;

	data = ei->data;

	return (xstrdup(data->tag));
}
