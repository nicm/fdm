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
#include "match.h"

int	match_in_cache_match(struct mail_ctx *, struct expritem *);
void	match_in_cache_desc(struct expritem *, char *, size_t);

struct match match_in_cache = {
	"in-cache",
	match_in_cache_match,
	match_in_cache_desc
};

int
match_in_cache_match(struct mail_ctx *mctx, struct expritem *ei)
{
	struct match_in_cache_data	*data = ei->data;
	struct account			*a = mctx->account;
	struct mail			*m = mctx->mail;
	char				*key;
	struct cache			*cache;

#ifndef DB
	log_warnx("%s: caches not enabled", a->name);
	return (MATCH_ERROR);
#endif

	key = replacestr(&data->key, m->tags, m, &m->rml);
	if (key == NULL || *key == '\0') {
		log_warnx("%s: empty key", a->name);
		goto error;
	}
	log_debug2("%s: matching to cache %s: %s", a->name, data->path, key);

	TAILQ_FOREACH(cache, &conf.caches, entry) {
		if (strcmp(data->path, cache->path) == 0) {
			if (open_cache(a, cache) != 0)
				goto error;
			if (db_contains(cache->db, key)) {
				xfree(key);
				return (MATCH_TRUE);
			}
			xfree(key);
			return (MATCH_FALSE);
		}
	}
	log_warnx("%s: cache %s not declared", a->name, data->path);

error:
	if (key != NULL)
		xfree(key);
	return (MATCH_ERROR);
}

void
match_in_cache_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_in_cache_data	*data = ei->data;

	xsnprintf(buf, len,
	    "in-cache \"%s\" key \"%s\"", data->path, data->key.str);
}
