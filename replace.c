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

void	initmap(char *[REPL_LEN], struct account *, struct action *, char *);

void
initmap(char *map[REPL_LEN], struct account *a, struct action *t, char *s)
{
	static char	 H[5], M[5], S[5], d[5], m[5], y[5], W[5], Y[5], Q[5];
	struct tm	*tm;
	time_t		 tt;

	if (a != NULL)
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
		if (snprintf(H, sizeof H, "%.2d", tm->tm_hour) == -1)
			fatal("snprintf");
		map[REPL_IDX('H')] = H;
		if (snprintf(M, sizeof M, "%.2d", tm->tm_min) == -1)
			fatal("snprintf");
		map[REPL_IDX('M')] = M;
		if (snprintf(S, sizeof S, "%.2d", tm->tm_sec) == -1)
			fatal("snprintf");
		map[REPL_IDX('S')] = S;
		if (snprintf(d, sizeof d, "%.2d", tm->tm_mday) == -1)
			fatal("snprintf");
		map[REPL_IDX('d')] = d;
		if (snprintf(m, sizeof m, "%.2d", tm->tm_mon) == -1)
			fatal("snprintf");
		map[REPL_IDX('m')] = m;
		if (snprintf(y, sizeof y, "%.4d", 1900 + tm->tm_year) == -1)
			fatal("snprintf");
		map[REPL_IDX('y')] = y;
		if (snprintf(W, sizeof W, "%d", tm->tm_wday) == -1)
			fatal("snprintf");
		map[REPL_IDX('W')] = W;
		if (snprintf(Y, sizeof Y, "%.2d", tm->tm_yday) == -1)
			fatal("snprintf");
		map[REPL_IDX('Y')] = Y;
		if (snprintf(Q, sizeof Q, "%d", (tm->tm_mon - 1) / 3 + 1) == -1)
			fatal("snprintf");
		map[REPL_IDX('Q')] = Q;
	}
}

char *
replacepmatch(char *src, struct account *a, struct action *t, char *s,
    struct mail *m, int pmatch_valid, regmatch_t pmatch[NPMATCH])
{
	char	*map[REPL_LEN];
	char	*dst, *u;
	size_t	 len;
	u_int	 i;

	if (!pmatch_valid)
		return (replaceinfo(src, a, t, s));

	memset(map, 0, REPL_LEN * sizeof (char *));
	initmap(map, a, t, s);

	for (i = 0; i < NPMATCH; i++) {
		if (pmatch[i].rm_so >= pmatch[i].rm_eo)
			continue;
		len = pmatch[i].rm_eo - pmatch[i].rm_so;
		u = xmalloc(len + 1);
		memcpy(u, m->data + pmatch[i].rm_so, len);
		u[len] = '\0';
		map[REPL_IDX('0' + (char) i)] = u;
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
	char		*map[REPL_LEN];

	memset(map, 0, REPL_LEN * sizeof (char *));
	initmap(map, a, t, s);

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
	len = BUFSIZ;
	dst = xmalloc(len);

	for (ptr = src; *ptr != '\0'; ptr++) {
		switch (*ptr) {
		case '%':
			ch = *++ptr;
			if (ch == '\0')
				goto out;
			rp = NULL;
			if (REPL_IDX(ch) != -1)
				rp = map[REPL_IDX(ch)];
			if (rp == NULL) {
				if (ch == '%') {
					ENSURE_FOR(dst, len, off, 1);
					dst[off++] = '%';
				}
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
