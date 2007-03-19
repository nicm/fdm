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

#include <ctype.h>
#include <limits.h>
#include <string.h>

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

/*
 * Some mailers, notably AOL's, use the timezone string instead of an offset
 * from UTC. This is highly annoying: since there are duplicate abbreviations
 * it cannot be converted with absolute certainty. As it is only a few clients
 * do this anyway, don't even try particularly hard, just try to look it up
 * using tzset, which catches the few most common abbreviations.
 */
int
match_age_tzlookup(const char *tz, int *off)
{
	char		*saved_tz;
	struct tm	*tm;
	time_t		 t;

	saved_tz = getenv("TZ");
	if (saved_tz != NULL)
	    saved_tz = xstrdup(saved_tz);

	/* set the new timezone */
	if (setenv("TZ", tz, 1) != 0)
		return (1);
	tzset();

	/* get the time at epoch + one year */
	t = TIME_YEAR;
	tm = localtime(&t);

	/* and work out the timezone */
	if (strcmp(tz, tm->tm_zone) == 0)
		*off = tm->tm_gmtoff;

	/* restore the old timezone */
	if (saved_tz != NULL) {
		if (setenv("TZ", saved_tz, 1) != 0)
			return (1);
		xfree(saved_tz);
	} else
		unsetenv("TZ");
	tzset();

	return (0);
}

int
match_age_match(struct mail_ctx *mctx, struct expritem *ei)
{
	struct match_age_data	*data = ei->data;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	char			*s, *ptr, *endptr, *hdr;
	const char		*errstr;
	size_t			 len;
	struct tm		 tm;
	time_t			 then, now;
	long long		 diff;
	int			 tz;

	memset(&tm, 0, sizeof tm);

	hdr = find_header(m, "date", &len, 1);
	if (hdr == NULL || len == 0 || len > INT_MAX)
		goto invalid;
	/* make a copy of the header */
	xasprintf(&s, "%.*s", (int) len, hdr);

	/* skip spaces */
	ptr = s;
	while (*ptr != '\0' && isspace((int) *ptr))
		ptr++;

	/* parse the date */
	log_debug2("%s: found date header: %s", a->name, ptr);
	memset(&tm, 0, sizeof tm);
	endptr = strptime(ptr, "%a, %d %b %Y %H:%M:%S", &tm);
	if (endptr == NULL)
		endptr = strptime(ptr, "%d %b %Y %H:%M:%S", &tm);
	if (endptr == NULL) {
		xfree(s);
		goto invalid;
	}
	now = time(NULL);
	then = mktime(&tm);

	/* skip spaces */
	while (*endptr != '\0' && isspace((int) *endptr))
		endptr++;

	/* terminate the timezone */
	ptr = endptr;
	while (*ptr != '\0' && !isspace((int) *ptr))
		ptr++;
	*ptr = '\0';

	tz = strtonum(endptr, -2359, 2359, &errstr);
	if (errstr != NULL) {
		/* try it using tzset */
		if (match_age_tzlookup(endptr, &tz) != 0) {
			xfree(s);
			goto invalid;
		}
	}

	log_debug2("%s: mail timezone is: %+.4d", a->name, tz);
	then -= (tz / 100) * TIME_HOUR + (tz % 100) * TIME_MINUTE;
	if (then < 0) {
		xfree(s);
		goto invalid;
	}

	xfree(s);

	diff = difftime(now, then);
	log_debug2("%s: time difference is %lld (now %lld, then %lld)", a->name,
	    diff, (long long) now, (long long) then);
	if (diff < 0) {
		/* reset all ages in the future to zero */
		diff = 0;
	}

	/* mail reaching this point is not invalid, so return false if validity
	   is what is being tested for */
	if (data->time < 0)
		return (MATCH_FALSE);

	if (data->cmp == CMP_LT && diff < data->time)
		return (MATCH_TRUE);
	else if (data->cmp == CMP_GT && diff > data->time)
		return (MATCH_TRUE);
	return (MATCH_FALSE);

invalid:
	if (data->time < 0)
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
