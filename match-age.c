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
#include <time.h>

#include "fdm.h"
#include "match.h"

int	match_age_match(struct mail_ctx *, struct expritem *);
void	match_age_desc(struct expritem *, char *, size_t);

int	match_age_tzlookup(const char *, int *);

struct match match_age = {
	"age",
	match_age_match,
	match_age_desc
};

int
match_age_match(struct mail_ctx *mctx, struct expritem *ei)
{
	struct match_age_data	*data = ei->data;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	time_t			 then, now;
	long long		 diff;

	/* Get current and mail time. */
	now = time(NULL);
	if (mailtime(m, &then) != 0) {
		/* Invalid, so return true if testing validity, else false. */
		if (data->time < 0)
			return (MATCH_TRUE);
		return (MATCH_FALSE);
	}
	/* Not invalid, so return false if validity is being tested for. */
	if (data->time < 0)
		return (MATCH_FALSE);

	/* Work out the time difference. */
	diff = difftime(now, then);
	log_debug2("%s: time difference is %lld (now %lld, then %lld)", a->name,
	    diff, (long long) now, (long long) then);
	if (diff < 0) {
		/* Reset all ages in the future to zero. */
		diff = 0;
	}

	if (data->cmp == CMP_LT && diff < data->time)
		return (MATCH_TRUE);
	else if (data->cmp == CMP_GT && diff > data->time)
		return (MATCH_TRUE);
	return (MATCH_FALSE);
}

void
match_age_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_age_data	*data = ei->data;
	const char		*cmp = "";

	if (data->time < 0) {
		strlcpy(buf, "age invalid", len);
		return;
	}

	if (data->cmp == CMP_LT)
		cmp = "<";
	else if (data->cmp == CMP_GT)
		cmp = ">";
	xsnprintf(buf, len, "age %s %lld seconds", cmp, data->time);
}
