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

char		*replace(char *, struct strb *, struct mail *, struct rmlist *);
const char 	*submatch(char, struct mail *, struct rmlist *, size_t *);

void printflike3
add_tag(struct strb **tags, const char *key, const char *value, ...)
{
	va_list	ap;

	va_start(ap, value);
	strb_vadd(tags, key, value, ap);
	va_end(ap);
}

const char *
find_tag(struct strb *tags, const char *key)
{
	struct strbent	*sbe;

	sbe = strb_find(tags, key);
	if (sbe == NULL)
		return (NULL);

	return (STRB_VALUE(tags, sbe));
}

const char *
match_tag(struct strb *tags, const char *pattern)
{
	struct strbent	*sbe;

	sbe = strb_match(tags, pattern);
	if (sbe == NULL)
		return (NULL);

	return (STRB_VALUE(tags, sbe));
}

void
default_tags(struct strb **tags, const char *src)
{
	char		 rtime[128];
	struct tm	*tm;
	time_t		 t;

	strb_clear(tags);	

	if (src != NULL)
		add_tag(tags, "source", "%s", src);

	if (conf.host_name != NULL)
		add_tag(tags, "hostname", "%s", conf.host_name);

	t = time(NULL);
	if ((tm = localtime(&t)) != NULL) {
		/*
		 * Okay, in a struct tm, everything is zero-based (including
		 * month!) except day of the month which is one-based.
		 *
		 * To make thing clearer, strftime(3) measures everything as
		 * you would expect... except that day of the week runs from
		 * 0-6 but day of the year runs from 1-366.
		 *
		 * Fun fun fun.
		 */
		add_tag(tags, "hour", "%.2d", tm->tm_hour);
		add_tag(tags, "minute", "%.2d", tm->tm_min);
		add_tag(tags, "second", "%.2d", tm->tm_sec);
		add_tag(tags, "day", "%.2d", tm->tm_mday);
		add_tag(tags, "month", "%.2d", tm->tm_mon + 1);
		add_tag(tags, "year", "%.4d", 1900 + tm->tm_year);
		add_tag(tags, "year2", "%.2d", tm->tm_year % 100);
		add_tag(tags, "dayofweek", "%d", tm->tm_wday);
		add_tag(tags, "dayofyear", "%.2d", tm->tm_yday + 1);
		add_tag(tags, "quarter", "%d", tm->tm_mon / 3 + 1);
	}
	if (rfc822time(t, rtime, sizeof rtime) != NULL)
		add_tag(tags, "rfc822date", "%s", rtime);
}

void
update_tags(struct strb **tags, struct userdata *ud)
{
	add_tag(tags, "user", "%s", ud->name);
	add_tag(tags, "home", "%s", ud->home);
	add_tag(tags, "uid", "%lu", (u_long) ud->uid);
	add_tag(tags, "gid", "%lu", (u_long) ud->gid);
}

void
reset_tags(struct strb **tags)
{
	add_tag(tags, "user", "%s", "");
	add_tag(tags, "home", "%s", "");
	add_tag(tags, "uid", "%s", "");
	add_tag(tags, "gid", "%s", "");
}

char *
replacestr(struct replstr *rs, struct strb *tags, struct mail *m,
    struct rmlist *rml)
{
	return (replace(rs->str, tags, m, rml));
}

char *
replacepath(struct replpath *rp, struct strb *tags, struct mail *m,
    struct rmlist *rml, const char *home)
{
	char	*s, *t;

	s = replace(rp->str, tags, m, rml);
 	if ((t = expand_path(s, home)) == NULL)
		return (s);
	xfree(s);
	return (t);
}

const char *
submatch(char ch, struct mail *m, struct rmlist *rml, size_t *len)
{
	struct rm	*rm;

	if (rml == NULL || !rml->valid || m == NULL)
		return (NULL);

	rm = &rml->list[((u_char) ch) - '0'];
	if (!rm->valid)
		return (NULL);

	*len = rm->eo - rm->so;
	return (m->data + rm->so);
}

char *
replace(char *src, struct strb *tags, struct mail *m, struct rmlist *rml)
{
	const char	*tptr, *alias;
	char		*ptr, *tend, *dst, ch;
	size_t	 	 i, off, len, tlen;
	int		 strip;

	if (src == NULL)
		return (NULL);
	if (*src == '\0')
		return (xstrdup(""));

	off = 0;
	len = REPLBUFSIZE;
	dst = xmalloc(len);

	strip = 1;
	for (ptr = src; *ptr != '\0'; ptr++) {
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

			if (*ptr == ':') {
				strip = 0;
				ptr++;
			}
			if (ptr == tend)
				continue;

			*tend = '\0';
			if ((tptr = find_tag(tags, ptr)) == NULL) {
				*tend = ']';
				ptr = tend;
				continue;
			}
			tlen = strlen(tptr);
			*tend = ']';

			ptr = tend;
			break;
		case ':':
			ch = *++ptr;
			if (ch >= '0' && ch <= '9') {
				tptr = submatch(ch, m, rml, &tlen);
				if (tptr == NULL)
					continue;
				strip = 0;
				break;
			}

			ENSURE_FOR(dst, len, off, 1);
			dst[off++] = ch;
			continue;
		default:
			if (ch >= '0' && ch <= '9') {
				tptr = submatch(ch, m, rml, &tlen);
				if (tptr == NULL)
					continue;
				break;
			}

			alias = NULL;
			if (ALIAS_IDX((u_char) ch) != -1)
				alias = aliases[ALIAS_IDX((u_char) ch)];
			if (alias == NULL)
				continue;

			if ((tptr = find_tag(tags, alias)) == NULL)
				continue;
			tlen = strlen(tptr);
			break;
		}

		if (tlen == 0)
			continue;
		ENSURE_FOR(dst, len, off, tlen);
		if (!strip) {
			memcpy(dst + off, tptr, tlen);
			off += tlen;
			continue;
		}
		for (i = 0; i < tlen; i++) {
			if (strchr(conf.strip_chars, tptr[i]) == NULL)
				dst[off++] = tptr[i];
		}
	}

out:
	ENSURE_FOR(dst, len, off, 1);
	dst[off] = '\0';

	return (dst);
}
