/* $Id$ */

/*
 * Copyright (c) 2008 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <pwd.h>

#include "fdm.h"

struct userdata *
passwd_lookup(const char *user)
{
	struct passwd	*pw;
	struct userdata	*ud;
	uid_t		 uid;
	const char	*errstr;

	if ((pw = getpwnam(user)) == NULL) {
		endpwent();
		uid = strtonum(user, 0, UID_MAX, &errstr);
		if (errstr != NULL)
			return (NULL);
		if ((pw = getpwuid(uid)) == NULL) {
			endpwent();
			return (NULL);
		}
	}

	ud = xmalloc(sizeof *ud);

	ud->name = xstrdup(pw->pw_name);
	ud->home = xstrdup(pw->pw_dir);

	ud->uid = pw->pw_uid;
	ud->gid = pw->pw_gid;

	endpwent();
	return (ud);
}
