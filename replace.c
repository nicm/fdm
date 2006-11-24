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

char *
replacepmatch(char *src, struct mail *m, regmatch_t pmatch[NPMATCH])
{
	char	*map[REPL_LEN];
	char	*dst, *s;
	size_t	 len;
	u_int	 i;

	memset(map, 0, sizeof map);

	for (i = 0; i < NPMATCH; i++) {
		if (pmatch[i].rm_so >= pmatch[i].rm_eo)
			continue;
		len = pmatch[i].rm_eo - pmatch[i].rm_so;
		s = xmalloc(len + 1);
		memcpy(s, m->data + pmatch[i].rm_so, len);
		s[len] = '\0';
		map[REPL_IDX('0' + (char) i)] = s;
	}

	dst = replace(src, map);

	for (i = 0; i < NPMATCH; i++) {
		if (map[REPL_IDX('0' + (char) i)] != NULL)
			xfree(map[REPL_IDX('0' + (char) i)]);
	}

	return (dst);
}

char *
replaceinfo(char *src, struct account *a, struct action *t, char *s)
{
	char		*map[REPL_LEN], H[5], M[5], S[5], d[5], m[5], y[5];
	char		 W[5], Y[5], Q[5];
	struct tm	*tm;
	time_t		 tt;

	memset(map, 0, sizeof map);

	map[REPL_IDX('a')] = a->name;
	map[REPL_IDX('s')] = s;
	map[REPL_IDX('h')] = conf.info.home;
	map[REPL_IDX('n')] = conf.info.uid;
	if (t != NULL)
		map[REPL_IDX('t')] = t->name;
	map[REPL_IDX('u')] = conf.info.user;

	/* time and date */
	tt = time(NULL);
	tm = localtime(&tt);
	if (tm != NULL) {
		xsnprintf(H, sizeof H, "%.2d", tm->tm_hour);
		map[REPL_IDX('H')] = H;
		xsnprintf(M, sizeof M, "%.2d", tm->tm_min);
		map[REPL_IDX('M')] = M;
		xsnprintf(S, sizeof S, "%.2d", tm->tm_sec);
		map[REPL_IDX('S')] = S;
		xsnprintf(d, sizeof d, "%.2d", tm->tm_mday);
		map[REPL_IDX('d')] = d;
		xsnprintf(m, sizeof m, "%.2d", tm->tm_mon);
		map[REPL_IDX('m')] = m;
		xsnprintf(y, sizeof y, "%.4d", 1900 + tm->tm_year);
		map[REPL_IDX('y')] = y;
		xsnprintf(W, sizeof W, "%d", tm->tm_wday);
		map[REPL_IDX('W')] = W;
		xsnprintf(Y, sizeof Y, "%.2d", tm->tm_yday);
		map[REPL_IDX('Y')] = Y;
		xsnprintf(Q, sizeof Q, "%d", (tm->tm_mon - 1) / 3 + 1);
		map[REPL_IDX('Q')] = Q;
	}

	return (replace(src, map));
}

char *
replace(char *src, char *map[REPL_LEN])
{
	char		*ptr, *dst, *rp, ch;
	size_t	 	 off, len, rl;

	if (src == NULL || *src == '\0')
		return (NULL);

	off = 0;
	len = 1024;
	dst = xmalloc(len);

	for (ptr = src; *ptr != '\0'; ptr++) {
		switch (*ptr) {
		case '%':
			ch = *++ptr;
			if (ch == '\0') {
				ENSURE_FOR(dst, len, off, 1);
				dst[off++] = '%';
				goto out;
			}
			rp = NULL;
			if (REPL_IDX(ch) != -1)
				rp = map[REPL_IDX(ch)];
			if (rp == NULL) {
				ENSURE_FOR(dst, len, off, 2);
				dst[off++] = '%';
				dst[off++] = ch;
				break;
			}

			rl = strlen(rp);
			ENSURE_FOR(dst, len, off, rl);
			memcpy(dst + off, rp, rl);
			off += rl;
			break;
		default:
			ENSURE_FOR(dst, len, off, 1);
			dst[off++] = *ptr;
			break;
		}
	}

out:
	ENSURE_FOR(dst, len, off, 1);
	dst[off] = '\0';

	return (dst);
}
