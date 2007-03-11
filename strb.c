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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "fdm.h"

void	*strb_address(struct strb *, const char *);

void
strb_create(struct strb **sbp)
{
	*sbp = xmalloc(sizeof **sbp);
	strb_clear(sbp);
}

void
strb_clear(struct strb **sbp)
{
	struct strb	*sb = *sbp;

	sb->ent_used = 0;
	sb->ent_max = STRBENTRIES;

	sb->str_size = STRBBLOCK;
	sb->str_used = 0;

	sb = *sbp = xrealloc(sb, 1, STRB_SIZE(sb));
	memset(STRB_ENTRY(sb, 0), 0, STRB_ENTSIZE(sb));
}

void
strb_destroy(struct strb **sbp)
{
	xfree(*sbp);
	*sbp = NULL;
}

void
strb_dump(struct strb *sb, const char *prefix, void (*p)(const char *, ...))
{
	struct strbent	*sbe;
	u_int		 i;

	for (i = 0; i < sb->ent_used; i++) {
		sbe = STRB_ENTRY(sb, i);
		p("%s: %s: %s", prefix, STRB_KEY(sb, sbe), STRB_VALUE(sb, sbe));
	}
}

void
strb_add(struct strb **sbp, const char *key, const char *value, ...)
{
	va_list	ap;

	va_start(ap, value);
	strb_vadd(sbp, key, value, ap);
	va_end(ap);
}
	
void
strb_vadd(struct strb **sbp, const char *key, const char *value, va_list ap)
{
	struct strb	*sb = *sbp;
	size_t		 size, keylen, valuelen;
	u_int		 n;
	struct strbent	 sbe;
	void		*sbep;
	char		*vp;

	keylen = strlen(key) + 1;
	
	/*
	 * glibc's vsnprintf is buggy and segfaults on ppc when writing directly
	 * into the string buffer. I haven't got access to a ppc machine to
	 * investigate this in detail myself but I guess it is an alignment 
	 * problem. OS X and OpenBSD/ppc appear to be fine. So, instead of
	 * writing directly, we asprintf to a buffer and memcpy it later.
	 */
	valuelen = xvasprintf(&vp, value, ap) + 1;

	sbep = STRB_ENTRY(sb, 0);
	size = sb->str_size;
	while (sb->str_size - sb->str_used < keylen + valuelen) {
		if (STRB_SIZE(sb) > SIZE_MAX / 2)
			fatalx("strb_add: size too large");
		sb->str_size *= 2;
	}
	if (size != sb->str_size) {
		sb = *sbp = xrealloc(sb, 1, STRB_SIZE(sb));
		memmove(STRB_ENTRY(sb, 0), sbep, STRB_ENTSIZE(sb));
		memset(((char *) sb) + (sizeof *sb) + size, 0,
		    sb->str_size - size);
	}

	sbep = strb_address(sb, key);
	if (sbep == NULL) {
		if (sb->ent_used > sb->ent_max) {
			/* allocate some more */
			if (sb->ent_max > UINT_MAX / 2) /* XXX */
				fatalx("strb_add: ent_max too large");
			n = sb->ent_max;
			
			sb->ent_max *= 2;
			sb = *sbp = xrealloc(sb, 1, STRB_SIZE(sb));

			memset(STRB_ENTRY(sb, n), 0, STRB_ENTSIZE(sb) / 2);
		}

		sbep = STRB_ENTRY(sb, sb->ent_used);
		sb->ent_used++;

		sbe.key = sb->str_used;
		memcpy(STRB_KEY(sb, &sbe), key, keylen);
		sb->str_used += keylen;
	} else
		memcpy(&sbe, sbep, sizeof sbe);
	sbe.value = sb->str_used;
	memcpy(STRB_VALUE(sb, &sbe), vp, valuelen);
	xfree(vp);
	sb->str_used += valuelen;

	memcpy(sbep, &sbe, sizeof sbe);
}

void *
strb_address(struct strb *sb, const char *key)
{
	struct strbent	 sbe;
	u_int		  i;

	for (i = 0; i < sb->ent_used; i++) {
		memcpy(&sbe, STRB_ENTRY(sb, i), sizeof sbe);
		if (strcmp(key, STRB_KEY(sb, &sbe)) == 0)
			return (STRB_ENTRY(sb, i));
	}
	return (NULL);
}

struct strbent *
strb_find(struct strb *sb, const char *key)
{
	static struct strbent	 sbe;
	void			*sbep;

	sbep = strb_address(sb, key);
	if (sbep == NULL)
		return (NULL);
	memcpy(&sbe, sbep, sizeof sbe);
	return (&sbe);
}

struct strbent *
strb_match(struct strb *sb, const char *patt)
{
	static struct strbent	 sbe;
	u_int		 	 i;

	for (i = 0; i < sb->ent_used; i++) {
		memcpy(&sbe, STRB_ENTRY(sb, i), sizeof sbe);
		if (fnmatch(patt, STRB_KEY(sb, &sbe), 0) == 0)
			return (&sbe);
	}
	return (NULL);
}

