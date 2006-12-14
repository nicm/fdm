/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm@users.sourceforge.net>
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
#include <sys/stat.h>

#include <db.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "fdm.h"

struct cache *
cache_open(char *path, char **cause)
{
	struct cache	*cc;

	cc = xmalloc(sizeof *cc);
	cc->path = xstrdup(path);
	
	cc->db = dbopen(cc->path, O_RDWR, 0, DB_HASH, NULL);
	if (cc->db == NULL) {
		if (errno != ENOENT) {
			xasprintf(cause, "%s: %s", cc->path, strerror(errno));
 			xfree(cc);
			return (NULL);
		}
		
		cc->db = dbopen(cc->path, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR,
		    DB_HASH, NULL);
		if (cc->db == NULL) {
			xasprintf(cause, "%s: %s", cc->path, strerror(errno));
 			xfree(cc);
			return (NULL);
		}
	}
	       
	return (cc);
}
void
cache_close(struct cache *cc)
{
	cc->db->close(cc->db);

	xfree(cc->path);
	xfree(cc);
}

u_int
cache_compact(struct cache *cc, long long age, u_int *total)
{
	struct cacheent *ce;
	DBT		 key, data;
	int		 error;
	u_int		 n, i;
	time_t		 t;
	uint64_t	 threshold;
	char		*s;
	struct strings	 keys;

	t = time(NULL);
	if (age > t)
		threshold = 0;
	else
		threshold = t - age;

	ARRAY_INIT(&keys);
	n = 0;
	if (total != NULL)
		*total = 0;

	if ((error = cc->db->seq(cc->db, &key, &data, R_FIRST)) == -1)
		fatal("db seq");
	while (error == 0) {
		if (total != NULL)
			(*total)++;

		if (data.size != sizeof *ce)
			fatal("db corrupted");
		ce = data.data;
		
		if (letoh64(ce->added) < threshold) {
			xasprintf(&s, "%.*s", (int) key.size, 
			    (char *) key.data);
			ARRAY_ADD(&keys, s, char *);
			n++;
		}

		if ((error = cc->db->seq(cc->db, &key, &data, R_NEXT)) == -1)
			fatal("db seq");		
	}

	for (i = 0; i < ARRAY_LENGTH(&keys); i++) {
		s = ARRAY_ITEM(&keys, i, char *);
		key.data = s;
		key.size = strlen(s);
		if (cc->db->del(cc->db, &key, 0) == -1)
			fatal("db del");
		xfree(s);
	}
	ARRAY_FREE(&keys);

	if (n > 0)
		cc->db->sync(cc->db, 0);

	return (n);
}

void
cache_add(struct cache *cc, char *item)
{
	struct cacheent	ce;
	DBT		key, data;
	time_t		t;

	t = time(NULL);

	key.data = item;
	key.size = strlen(item);

	data.data = &ce;
	data.size = sizeof ce;

	ce.added = htole64((uint64_t) t);

	if (cc->db->put(cc->db, &key, &data, 0) == -1)
		fatal("db put");

	cc->db->sync(cc->db, 0);
}

int
cache_contains(struct cache *cc, char *item)
{
	DBT	key, data;
	int	error;

	key.data = item;
	key.size = strlen(item);

	if ((error = cc->db->get(cc->db, &key, &data, 0)) == -1)
		fatal("db get");

	return (!error);
}
