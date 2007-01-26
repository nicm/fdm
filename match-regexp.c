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

int	regexp_match(struct match_ctx *, struct expritem *);
char   *regexp_desc(struct expritem *);

struct match match_regexp = { regexp_match, regexp_desc };

int
regexp_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct regexp_data	*data = ei->data;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	regmatch_t	        *pmatch = mctx->pmatch;
	int			 res;
	char		        *cause;

	if (data->area == AREA_BODY && m->body == -1)
		return (MATCH_FALSE);

	switch (data->area) {
	case AREA_HEADERS:
		pmatch[0].rm_so = 0;
		if (m->body == -1)
			pmatch[0].rm_eo = m->size;
		else
			pmatch[0].rm_eo = m->body;
		break;
	case AREA_BODY:
		pmatch[0].rm_so = m->body;
		pmatch[0].rm_eo = m->size;
		break;
	case AREA_ANY:
		pmatch[0].rm_so = 0;
		pmatch[0].rm_eo = m->size;
		break;
	}

	res = re_execute(&data->re, m->data, NPMATCH, pmatch, REG_STARTEND,
	    &cause);
	if (res == -1) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (MATCH_ERROR);
	}

	mctx->pmatch_valid = 1;
	if (res == 0)
		return (MATCH_FALSE);
	return (MATCH_TRUE);
}

char *
regexp_desc(struct expritem *ei)
{
	struct regexp_data	*data = ei->data;
	const char		*area = NULL;
	char			*s;

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

	xasprintf(&s, "regexp \"%s\" in %s", data->re.str, area);
	return (s);
}
