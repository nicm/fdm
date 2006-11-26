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
#include <string.h>

#include "fdm.h"

int	age_match(struct match_ctx *, struct expritem *);
char   *age_desc(struct expritem *);

struct match match_age = { age_match, age_desc };

int
age_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct age_data	*data = ei->data;
	struct account	*a = mctx->account;
	struct mail	*m = mctx->mail;
	char		*s, *ptr, *endptr, *hdr, tmp[256];
	const char	*errstr;
	size_t		 len, off;
	struct tm	 tm;
	time_t		 then, now;
	long long	 diff, t;
	int		 tz;

	memset(&tm, 0, sizeof tm);

	hdr = find_header(m, "Date:", &len);
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

	if (strcmp(endptr, "GMT") == 0)
		tz = 0;
	else {
		tz = strtonum(endptr, -9999, 9999, &errstr);
		if (errstr != NULL) {
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
	if (diff < 0)
		goto invalid;

	/* mails reaching this point is not invalid, so return false if
	   validity is what is being tested for */
	if (data->time < 0)
		return (MATCH_FALSE);

	t = diff;
	off = 0;
	len = sizeof tmp;
	off += snprintf(tmp + off, len - off, "%lld y, ", t / TIME_YEAR);
	off += snprintf(tmp + off, len - off, "%lld m, ", t / TIME_MONTH);
	off += snprintf(tmp + off, len - off, "%lld w, ", t / TIME_WEEK);
	off += snprintf(tmp + off, len - off, "%lld d, ", t / TIME_DAY);
	off += snprintf(tmp + off, len - off, "%lld h, ", t / TIME_HOUR);
	off += snprintf(tmp + off, len - off, "%lld m, ", t / TIME_MINUTE);
	off += snprintf(tmp + off, len - off, "%lld s", t);
	log_debug2("%s: mail age is: %s", a->name, tmp);
	
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

char *
age_desc(struct expritem *ei)
{
	struct age_data	*data = ei->data;
	char			*s;
	const char		*cmp = "";

	if (data->time < 0)
		return (xstrdup("age invalid"));

	if (data->cmp == CMP_LT)
		cmp = "<";
	else if (data->cmp == CMP_GT)
		cmp = ">";
	xasprintf(&s, "age %s %lld seconds", cmp, data->time);
	return (s);
}
