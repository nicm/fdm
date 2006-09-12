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
 
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

char *
replaceinfo(char *src, struct account *a, struct action *t)
{
	char	*map[REPL_LEN];

	memset(map, 0, sizeof map);
	map[REPL_IDX('a')] = a->name;
	map[REPL_IDX('h')] = conf.info.home;
	map[REPL_IDX('n')] = conf.info.uid;
	map[REPL_IDX('t')] = t->name;
	map[REPL_IDX('u')] = conf.info.user;

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
			if (ch == '\0')
				break;
			rp = NULL;
			if (REPL_IDX(ch) != -1)
				rp = map[REPL_IDX(ch)];
			if (rp == NULL) {
				ENSURE_SIZE(dst, len, off + 2);
				dst[off++] = '%';
				dst[off++] = ch;
				break;
			}

			rl = strlen(rp);
			ENSURE_SIZE(dst, len, off + rl);
			memcpy(dst + off, rp, rl);
			off += rl;
			break;
		default:
			ENSURE_SIZE(dst, len, off + 1);
			dst[off++] = *ptr;
			break;
		}
	}
	
	ENSURE_SIZE(dst, len, off + 1);
	dst[off] = '\0';

	return (dst);
}
