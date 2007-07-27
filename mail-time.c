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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fdm.h"

int	tzlookup(const char *, int *);

char *
rfc822time(time_t t, char *buf, size_t len)
{
	struct tm      *tm;
	size_t		n;

	tm = localtime(&t);
	if ((n = strftime(buf, len, "%a, %d %b %Y %H:%M:%S %z", tm)) == 0)
		return (NULL);
	if (n == len)
		return (NULL);
	return (buf);
}

/*
 * Some mailers, notably AOL's, use the timezone string instead of an offset
 * from UTC. A limited set of these are permitted by RFC822, but it is still
 * highly annoying: others can appear, and since there are duplicate
 * abbreviations it cannot be converted with absolute certainty. As it is only
 * a few clients do this anyway, don't even try particularly hard, just try to
 * look it up using tzset, which catches the few most common abbreviations.
 */
int
tzlookup(const char *tz, int *off)
{
	char		*saved_tz;
	struct tm	*tm;
	time_t		 t;

	saved_tz = getenv("TZ");
	if (saved_tz != NULL)
		saved_tz = xstrdup(saved_tz);

	/* Set the new timezone. */
	if (setenv("TZ", tz, 1) != 0)
		goto error;
	tzset();

	/* Get the time at epoch + one year. */
	t = TIME_YEAR;
	tm = localtime(&t);

	/* And work out the timezone. */
	if (strcmp(tz, tm->tm_zone) != 0)
		goto error;
	*off = tm->tm_gmtoff;

	/* Restore the old timezone. */
	if (saved_tz != NULL) {
		if (setenv("TZ", saved_tz, 1) != 0)
			goto error;
		xfree(saved_tz);
	} else
		unsetenv("TZ");
	tzset();

	return (0);

error:
	if (saved_tz != NULL)
		xfree(saved_tz);
	return (-1);
}

int
mailtime(struct mail *m, time_t *tim)
{
	char		*s, *ptr, *endptr, *hdr;
	const char	*errstr;
	size_t		 len;
	struct tm	 tm;
	int		 tz;

	hdr = find_header(m, "date", &len, 1);
	if (hdr == NULL || len == 0 || len > INT_MAX)
		return (-1);
	/* Make a copy of the header. */
	xasprintf(&s, "%.*s", (int) len, hdr);

	/* Skip spaces. */
	ptr = s;
	while (*ptr != '\0' && isspace((u_char) *ptr))
		ptr++;

	/* Parse the date. */
	memset(&tm, 0, sizeof tm);
	endptr = strptime(ptr, "%a, %d %b %Y %H:%M:%S", &tm);
	if (endptr == NULL)
		endptr = strptime(ptr, "%d %b %Y %H:%M:%S", &tm);
	if (endptr == NULL)
		goto invalid;
	*tim = mktime(&tm);

	/* Skip spaces. */
	while (*endptr != '\0' && isspace((u_char) *endptr))
		endptr++;

	/* Terminate the timezone. */
	ptr = endptr;
	while (*ptr != '\0' && !isspace((u_char) *ptr))
		ptr++;
	*ptr = '\0';

	tz = strtonum(endptr, -2359, 2359, &errstr);
	if (errstr != NULL) {
		/* Try it using tzset. */
		if (tzlookup(endptr, &tz) != 0)
			goto invalid;
	}
	*tim -= (tz / 100) * TIME_HOUR + (tz % 100) * TIME_MINUTE;
	if (*tim < 0)
		goto invalid;

	xfree(s);
	return (0);

invalid:
	xfree(s);
	return (-1);
}
