/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicholas.marriott@gmail.com>
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

#include <fcntl.h>
#include <signal.h>
#include <string.h>
#ifndef _PUBLIC_
#define _PUBLIC_
#endif
#include <tdb.h>

#include "fdm.h"

int	db_print_item(TDB_CONTEXT *, TDB_DATA, TDB_DATA, void *);
int	db_expire_item(TDB_CONTEXT *, TDB_DATA, TDB_DATA, void *);
int	db_clear_item(TDB_CONTEXT *, TDB_DATA, TDB_DATA, void *);

TDB_CONTEXT *
db_open(char *path)
{
	TDB_CONTEXT	*db;

#ifndef DB_UNSAFE
	db = tdb_open(path, 0, 0, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
#else
	db = tdb_open(path, 0, TDB_NOLOCK, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
#endif
	return (db);
}

void
db_close(TDB_CONTEXT *db)
{
	tdb_close(db);
}

int
db_add(TDB_CONTEXT *db, char *k)
{
	TDB_DATA		key, value;
	struct cacheitem	v;
	uint64_t		tim;

	memset(&v, 0, sizeof v);
	tim = time(NULL);
	v.tim = htole64(tim);

	key.dptr = k;
	key.dsize = strlen(k);

	value.dptr = (char *) &v;
	value.dsize = sizeof v;

	return (tdb_store(db, key, value, TDB_REPLACE));
}

int
db_remove(TDB_CONTEXT *db, char *k)
{
	TDB_DATA		key;

	key.dptr = k;
	key.dsize = strlen(k);

	return (tdb_delete(db, key));
}

int
db_contains(TDB_CONTEXT *db, char *k)
{
	TDB_DATA	key;

	key.dptr = k;
	key.dsize = strlen(k);

	return (tdb_exists(db, key));
}

int
db_size(TDB_CONTEXT *db)
{
	return (tdb_traverse(db, NULL, NULL));
}

int
db_print_item(
    unused TDB_CONTEXT *tdb, unused TDB_DATA key, TDB_DATA value, void *ptr)
{
	void			(*p)(const char *, ...) = ptr;
	struct cacheitem	v;
	uint64_t		tim;

	if (value.dsize != sizeof v)
		return (-1);
	memcpy(&v, value.dptr, sizeof v);

	tim = letoh64(v.tim);
	p("%.*s %llu", key.dsize, key.dptr, (unsigned long long) tim);

	return (0);
}

int
db_print(TDB_CONTEXT *db, void (*p)(const char *, ...))
{
	if (tdb_traverse(db, db_print_item, p) == -1)
		return (-1);
	return (0);
}

int
db_expire_item(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA value, void *ptr)
{
	uint64_t	       *lim = ptr;
	struct cacheitem	v;

	if (value.dsize != sizeof v)
		return (-1);
	memcpy(&v, value.dptr, sizeof v);

	if (letoh64(v.tim) < *lim)
		return (tdb_delete(tdb, key));
	return (0);
}

int
db_expire(TDB_CONTEXT *db, uint64_t age)
{
	uint64_t	lim;

	lim = time(NULL);
	if (lim <= age)
		return (0);
	lim -= age;

	if (tdb_traverse(db, db_expire_item, &lim) == -1)
		return (-1);
	return (0);
}

int
db_clear_item(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA value, unused void *ptr)
{
	if (value.dsize != sizeof (struct cacheitem))
		return (-1);

	return (tdb_delete(tdb, key));
}

int
db_clear(TDB_CONTEXT *db)
{
	if (tdb_traverse(db, db_clear_item, NULL) == -1)
		return (-1);
	return (0);
}
