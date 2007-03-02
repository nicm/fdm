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

#include <fnmatch.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "fdm.h"

#define ALIAS_IDX(ch) /* LINTED */ 				\
	(((ch) >= 'a' && (ch) <= 'z') ? (ch) - 'a' :       	\
	(((ch) >= 'A' && (ch) <= 'Z') ? 26 + (ch) - 'A' : -1))

static const char *aliases[] = {
	"account", 	/* a */
	NULL, 		/* b */
	NULL, 		/* c */
	"day", 		/* d */
	NULL, 		/* e */
	NULL, 		/* f */
	NULL, 		/* g */
	"home", 	/* h */
	NULL, 		/* i */
	NULL, 		/* j */
	NULL, 		/* l */
	NULL, 		/* l */
	"month", 	/* m */
	"uid", 		/* n */
	NULL, 		/* o */
	NULL, 		/* p */
	NULL, 		/* q */
	NULL, 		/* r */
	"source", 	/* s */
	"action", 	/* t */
	"user", 	/* u */
	NULL, 		/* v */
	NULL, 		/* w */
	NULL, 		/* x */
	"year", 	/* y */
	NULL, 		/* z */

	NULL, 		/* A */
	NULL, 		/* B */
	NULL, 		/* C */
	NULL, 		/* D */
	NULL, 		/* E */
	NULL, 		/* F */
	NULL, 		/* G */
	"hour", 	/* H */
	NULL, 		/* I */
	NULL, 		/* J */
	NULL, 		/* K */
	NULL, 		/* L */
	"minute", 	/* M */
	NULL, 		/* N */
	NULL, 		/* O */
	NULL, 		/* P */
	"quarter",	/* Q */
	NULL, 		/* R */
	"second",	/* S */
	NULL, 		/* T */
	NULL, 		/* U */
	NULL, 		/* V */
	"dayofweek", 	/* W */
	NULL, 		/* X */
	"dayofyear", 	/* Y */
	NULL, 		/* Z */
};

void printflike3
add_tag(struct tags *tags, const char *name, const char *fmt, ...)
{
	struct tag	*tag;
	va_list		 ap;
	int		 len;

	if ((tag = find_tag(tags, name)) == NULL) {
		ARRAY_EXPAND(tags, 1, struct tag);
		tag = &ARRAY_LAST(tags, struct tag);
	}

	if (strlcpy(tag->name, name, sizeof tag->name) >= sizeof tag->name)
		goto error;

	va_start(ap, fmt);
	len = xvsnprintf(tag->value, sizeof tag->value, fmt, ap);
	va_end(ap);
	if ((size_t) len >= sizeof tag->value)
		goto error;

	return;

error:
	/* XXX this sucks */
	ARRAY_TRUNC(tags, 1, struct tag);
}

struct tag *
find_tag(struct tags *tags, const char *name)
{
	struct tag	*tag;
	u_int		 i;

	for (i = 0; i < ARRAY_LENGTH(tags); i++) {
		tag = &ARRAY_ITEM(tags, i, struct tag);
		if (strcmp(name, tag->name) == 0)
			return (tag);
	}

	return (NULL);
}

struct tag *
match_tag(struct tags *tags, const char *name)
{
	struct tag	*tag;
	u_int		 i;

	for (i = 0; i < ARRAY_LENGTH(tags); i++) {
		tag = &ARRAY_ITEM(tags, i, struct tag);
		if (fnmatch(name, tag->name, 0) == 0)
			return (tag);
	}

	return (NULL);
}

void
default_tags(struct tags *tags, char *src, struct account *a)
{
	struct tm	*tm;
	time_t		 t;

	ARRAY_INIT(tags);

	add_tag(tags, "home", "%s", conf.info.home);
	add_tag(tags, "uid", "%s", conf.info.uid);
	add_tag(tags, "user", "%s", conf.info.user);

	if (src != NULL)
		add_tag(tags, "source", "%s", src);
	if (a != NULL)
		add_tag(tags, "account", "%s", a->name);

	t = time(NULL);
	if ((tm = localtime(&t)) != NULL) {
		add_tag(tags, "hour", "%.2d", tm->tm_hour);
		add_tag(tags, "minute", "%.2d", tm->tm_min);
		add_tag(tags, "second", "%.2d", tm->tm_sec);
		add_tag(tags, "day", "%.2d", tm->tm_mday);
		add_tag(tags, "month", "%.2d", tm->tm_mon);
		add_tag(tags, "year", "%.4d", 1900 + tm->tm_year);
		add_tag(tags, "dayofweek", "%d", tm->tm_wday);
		add_tag(tags, "dayofyear", "%.2d", tm->tm_yday);
		add_tag(tags, "quarter", "%d", (tm->tm_mon - 1) / 3 + 1);
	}
}

void
update_tags(struct tags *tags)
{
	add_tag(tags, "home", "%s", conf.info.home);
	add_tag(tags, "uid", "%s", conf.info.uid);
	add_tag(tags, "user", "%s", conf.info.user);
}

char *
replace(const char *src, struct tags *tags, struct mail *m, int pm_valid,
    regmatch_t pm[NPMATCH])
{
	struct tag	*tag;
	const char	*ptr, *tptr, *tend, *alias;
	char		*dst, name[MAXNAMESIZE], ch;
	size_t	 	 off, len, tlen;
	u_int		 idx;

	if (src == NULL || *src == '\0')
		return (NULL);

	off = 0;
	len = BUFSIZ;
	dst = xmalloc(len);

	for (ptr = src; *ptr != '\0'; ptr++) {
		alias = NULL;

		switch (*ptr) {
		case '%':
			break;
		default:
			ENSURE_FOR(dst, len, off, 1);
			dst[off++] = *ptr;
			continue;
		}

		switch (ch = *++ptr) {
		case '\0':
			goto out;
		case '%':
			ENSURE_FOR(dst, len, off, 1);
			dst[off++] = '%';
			continue;
		case '[':
			if ((tend = strchr(ptr, ']')) == NULL) {
				ENSURE_FOR(dst, len, off, 2);
				dst[off++] = '%';
				dst[off++] = '[';
				continue;
			}
			ptr++;
			if (tend - ptr >= MAXNAMESIZE) {
				ptr = tend;
				continue;
			}
			strlcpy(name, ptr, (tend - ptr) + 1);
			if ((tag = find_tag(tags, name)) == NULL) {
				ptr = tend;
				continue;
			}

			tptr = tag->value;
			tlen = strlen(tptr);

			ptr = tend;
			break;
		default:
			if (ch >= '0' && ch <= '9') {
				if (!pm_valid || m == NULL || pm == NULL)
					continue;
				idx = ((u_char) ch) - '0';
				if (pm[idx].rm_so >= pm[idx].rm_eo)
					continue;

				tptr = m->base + pm[idx].rm_so;
				tlen = pm[idx].rm_eo - pm[idx].rm_so;
				break;
			}

			if (ALIAS_IDX(ch) != -1)
				alias = aliases[ALIAS_IDX(ch)];
			if (alias == NULL)
				continue;

			if ((tag = find_tag(tags, alias)) == NULL)
				continue;
			tptr = tag->value;
			tlen = strlen(tptr);
			break;
		}

		ENSURE_FOR(dst, len, off, tlen);
		memcpy(dst + off, tptr, tlen);
		off += tlen;
	}

out:
	ENSURE_FOR(dst, len, off, 1);
	dst[off] = '\0';

	return (dst);
}
