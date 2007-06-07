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

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

struct cleanent {
	char			*path;

	TAILQ_ENTRY(cleanent)	 entry;
};
TAILQ_HEAD(, cleanent)		 cleanlist;

void
cleanup_check(void)
{
	if (!TAILQ_EMPTY(&cleanlist))
		fatalx("cleanup_check: list not empty");
}

void
cleanup_purge(void)
{
	struct cleanent	*cent;
	int		 saved_errno;

	/*
	 * This must be signal safe.
	 */

	saved_errno = errno;
 	TAILQ_FOREACH(cent, &cleanlist, entry) {
		if (unlink(cent->path) != 0) {
			write(STDERR_FILENO, "unlink failed\n", 14);
			_exit(1);
		}
	}
	errno = saved_errno;
}

void
cleanup_flush(void)
{
	sigset_t	 set, oset;
	struct cleanent	*cent;

	sigfillset(&set);
	if (sigprocmask(SIG_BLOCK, &set, &oset) < 0)
		fatal("sigprocmask");

	while (!TAILQ_EMPTY(&cleanlist)) {
		cent = TAILQ_FIRST(&cleanlist);
		TAILQ_REMOVE(&cleanlist, cent, entry);
		xfree(cent->path);
		xfree(cent);
	}

	if (sigprocmask(SIG_SETMASK, &oset, NULL) < 0)
		fatal("sigprocmask");
}

void
cleanup_register(const char *path)
{
	sigset_t	 set, oset;
	struct cleanent	*cent;

#if 0
	log_debug("cleanup_register: %s by %ld", path, (long) getpid());
#endif

	cent = xmalloc(sizeof *cent);
	cent->path = xstrdup(path);

	sigfillset(&set);
	if (sigprocmask(SIG_BLOCK, &set, &oset) < 0)
		fatal("sigprocmask");

	TAILQ_INSERT_HEAD(&cleanlist, cent, entry);

	if (sigprocmask(SIG_SETMASK, &oset, NULL) < 0)
		fatal("sigprocmask");
}

void
cleanup_deregister(const char *path)
{
	sigset_t	 set, oset;
	struct cleanent	*cent;

#if 0
 	log_debug("cleanup_deregister: %s by %ld", path, (long) getpid());
#endif

	sigfillset(&set);
	if (sigprocmask(SIG_BLOCK, &set, &oset) < 0)
		fatal("sigprocmask");

 	TAILQ_FOREACH(cent, &cleanlist, entry) {
		if (strcmp(cent->path, path) == 0) {
			TAILQ_REMOVE(&cleanlist, cent, entry);
			xfree(cent->path);
			xfree(cent);
			goto out;
		}
	}

	fatalx("cleanup_deregister: entry not found");

out:
	if (sigprocmask(SIG_SETMASK, &oset, NULL) < 0)
		fatal("sigprocmask");
}
