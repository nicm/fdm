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

#include "fdm.h"
#include "match.h"

int	match_regexp_match(struct mail_ctx *, struct expritem *);
void	match_regexp_desc(struct expritem *, char *, size_t);

struct match match_regexp = {
	"regexp",
	match_regexp_match,
	match_regexp_desc
};

int
match_regexp_match(struct mail_ctx *mctx, struct expritem *ei)
{
	struct match_regexp_data	*data = ei->data;
	struct account			*a = mctx->account;
	struct mail			*m = mctx->mail;
	int				 res;
	char			        *cause;
	size_t				 so, eo;

	so = 0;
	eo = m->size;
	switch (data->area) {
	case AREA_HEADERS:
		if (m->body == 0)
			return (MATCH_FALSE);
		eo = m->body;
		break;
	case AREA_BODY:
		so = m->body;
		break;
	case AREA_ANY:
		break;
	}
	log_debug3("%s: matching from %zu to %zu (size=%zu, body=%zu)", a->name,
	    so, eo, m->size, m->body);

	res = re_block(&data->re, m->data + so, eo - so, &m->rml, &cause);
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
match_regexp_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_regexp_data	*data = ei->data;
	const char			*area = NULL;

	switch (data->area) {
	case AREA_BODY:
		area = "body";
		break;
	case AREA_HEADERS:
		area = "headers";
		break;
	case AREA_ANY:
		area = "any";
		break;
	}

	xsnprintf(buf, len, "regexp \"%s\" in %s", data->re.str, area);
}
