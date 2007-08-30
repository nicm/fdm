/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
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
#include "match.h"

int	match_account_match(struct mail_ctx *, struct expritem *);
void	match_account_desc(struct expritem *, char *, size_t);

struct match match_account = {
	"account",
	match_account_match,
	match_account_desc
};

int
match_account_match(struct mail_ctx *mctx, struct expritem *ei)
{
	struct match_account_data	*data = ei->data;
	struct account			*a = mctx->account;
	struct mail			*m = mctx->mail;
	char				*s;
	u_int				 i;

	for (i = 0; i < ARRAY_LENGTH(data->accounts); i++) {
		s = replacestr(
		    &ARRAY_ITEM(data->accounts, i), m->tags, m, &m->rml);
		if (s == NULL || *s == '\0') {
			if (s != NULL)
				xfree(s);
			log_warnx("%s: empty account", a->name);
			return (MATCH_ERROR);
		}
		if (account_match(s, a->name)) {
			xfree(s);
			return (MATCH_TRUE);
		}
		xfree(s);
	}

	return (MATCH_FALSE);
}

void
match_account_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_account_data	*data = ei->data;
	char				*accounts;

	accounts = fmt_replstrs("account ", data->accounts);
	strlcpy(buf, accounts, len);
	xfree(accounts);
}
