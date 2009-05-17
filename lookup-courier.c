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

#ifdef LOOKUP_COURIER

#include <sys/types.h>

#include <courierauth.h>
#include <pwd.h>

#include "fdm.h"

/*
 * The mandatory callback in this API is stupid.
 */

int	courier_callback(struct authinfo *, void *);

struct userdata	*courier_udata;

int
courier_callback(struct authinfo *ai, unused void *data)
{
	struct passwd	*pw;

	courier_udata = xmalloc(sizeof *courier_udata);
	courier_udata->name = xstrdup(ai->address);
	courier_udata->home = xstrdup(ai->homedir);

	if (ai->sysusername != NULL) {
		if ((pw = getpwnam(ai->sysusername)) == NULL) {
			xfree(courier_udata);
			courier_udata = NULL;
			return (0);
		}
		courier_udata->uid = pw->pw_uid;
		courier_udata->gid = pw->pw_gid;
		endpwent();
	} else {
		courier_udata->uid = *ai->sysuserid;
		courier_udata->gid = ai->sysgroupid;
	}

	return (0);
}

struct userdata *
courier_lookup(const char *user)
{
	courier_udata = NULL;
	if (auth_getuserinfo(__progname, user, courier_callback, NULL) != 0)
		return (NULL);
	return (courier_udata);
}

#endif /* LOOKUP_COURIER */
