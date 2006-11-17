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

int	regexp_match(struct account *, struct mail *, struct expritem *);
char   *regexp_desc(struct expritem *);

struct match match_regexp = { "regexp", regexp_match, regexp_desc };

int
regexp_match(struct account *a, struct mail *m, struct expritem *ei)
{
	struct regexp_data	*data;
	regmatch_t	 	 pmatch;
	int			 res;

	data = ei->data;
	
	if (data->area == AREA_BODY && m->body == -1)
		return (0);

	switch (data->area) {
	case AREA_HEADERS:
		pmatch.rm_so = 0;
		if (m->body == -1)
			pmatch.rm_eo = m->size;
		else
			pmatch.rm_eo = m->body;
		break;
	case AREA_BODY:
		pmatch.rm_so = m->body;
		pmatch.rm_eo = m->size;
		break;
	case AREA_ANY:
		pmatch.rm_so = 0;
		pmatch.rm_eo = m->size;
		break;
	}
	
	res = regexec(&data->re, m->data, 0, &pmatch, REG_STARTEND);
	if (res != 0 && res != REG_NOMATCH) {
		log_warnx("%s: %s: regexec failed", a->name, data->re_s);
		return (-1);
	}

	return (res == 0);
}

char *
regexp_desc(struct expritem *ei)
{
	struct regexp_data	*data;
	const char		*area = NULL;
	char			*s;

	data = ei->data;

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

	xasprintf(&s, "\"%s\" in %s", data->re_s, area);
	return (s);
}
