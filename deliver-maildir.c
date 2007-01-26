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

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fdm.h"

int	 maildir_deliver(struct deliver_ctx *, struct action *);
void	 maildir_desc(struct action *, char *, size_t);

struct deliver deliver_maildir = { DELIVER_ASUSER, maildir_deliver,
				   maildir_desc };

int
maildir_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct account	*a = dctx->account;
	struct mail	*m = dctx->mail;
	static u_int	 delivered = 0;
	char		*path, ch;
	char	 	 host1[MAXHOSTNAMELEN], host2[MAXHOSTNAMELEN], *host;
	char	 	 name[MAXPATHLEN], src[MAXPATHLEN], dst[MAXPATHLEN];
	int	 	 fd, res = DELIVER_FAILURE;
	ssize_t	 	 n;
	size_t	 	 first, last;

	path = replacepmatch(t->data, a, t, m->src, m, dctx->pmatch_valid,
	    dctx->pmatch);
	if (path == NULL || *path == '\0') {
		log_warnx("%s: empty path", a->name);
		goto out;
	}
	log_debug("%s: saving to maildir %s", a->name, path);

	/* create the maildir directories */
	if (mkdir(path, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, path);
		goto out;
	}
	if (makepath(name, sizeof name, path, "cur") != 0) {
		log_warn("%s: %s: makepath", a->name, path);
		goto out;
	}
	if (mkdir(name, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, name);
		goto out;
	}
	if (makepath(name, sizeof name, path, "new") != 0) {
		log_warn("%s: %s: xsnprintf", a->name, path);
		goto out;
	}
	if (mkdir(name, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, name);
		goto out;
	}
	if (makepath(name, sizeof name, path, "tmp") < 0) {
		log_warn("%s: %s: xsnprintf", a->name, path);
		goto out;
	}
	if (mkdir(name, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, name);
		goto out;
	}

	if (gethostname(host1, sizeof host1) != 0)
		fatal("gethostname");

	/* replace '/' with "\057" and ':' with "\072". this is a bit
	   inefficient but sod it */
	last = strcspn(host1, "/:");
	if (host1[last] == '\0')
		host = host1;
	else {
		*host2 = '\0';

		first = 0;
		do {
			ch = host1[first + last];
			host1[first + last] = '\0';
			strlcat(host2, host1 + first, sizeof host2);
			switch (ch) {
			case '/':
				strlcat(host2, "\\057", sizeof host2);
				break;
			case ':':
				strlcat(host2, "\\072", sizeof host2);
				break;
			}
			host1[first + last] = ch;

			first += last + 1;
			last = strcspn(host1 + first, "/:");
		} while (ch != '\0');

		host = host2;
	}

restart:
	/* find a suitable name in tmp */
	do {
		if (xsnprintf(name, sizeof name, "%ld.%ld_%u.%s",
		    (long) time(NULL), (long) getpid(), delivered, host) < 0) {
			log_warn("%s: %s: xsnprintf", a->name, path);
			goto out;
		}

		if (xsnprintf(src, sizeof src, "%s/tmp/%s", path, name) < 0) {
			log_warn("%s: %s: xsnprintf", a->name, path);
			goto out;
		}

		cleanup_register(src);
		fd = open(src, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
		if (fd == -1 && errno != EEXIST) {
			cleanup_deregister(src);
			log_warn("%s: %s: open", a->name, src);
			goto out;
		} else if (fd == -1)
			cleanup_deregister(src);

		delivered++;
	} while (fd == -1);

	/* write the message */
	log_debug2("%s: writing to %s", a->name, src);
	n = write(fd, m->data, m->size);
	if (n < 0 || (size_t) n != m->size) {
		log_warn("%s: write", a->name);
		close(fd);
		unlink(src);
		cleanup_deregister(src);
		goto out;
	}
	close(fd);

	/* create the new path and attempt to link it. a failed link jumps
	   back to find another name in the tmp directory */
	if (xsnprintf(dst, sizeof dst, "%s/new/%s", path, name) < 0) {
		log_warn("%s: %s: xsnprintf", a->name, path);
		goto out;
	}
	log_debug2("%s: linking .../%s to .../%s", a->name,
	    src + strlen(path) + 1, dst + strlen(path) + 1);
	if (link(src, dst) != 0) {
		unlink(src);
		cleanup_deregister(src);
		if (errno == EEXIST) {
			log_debug2("%s: link failed", a->name);
			goto restart;
		}
		log_warn("%s: %s: link(\"%s\")", a->name, src, dst);
		goto out;
	}

	/* unlink the original tmp file */
	log_debug2("%s: unlinking .../%s", a->name, src + strlen(path) + 1);
	if (unlink(src) != 0) {
		cleanup_deregister(src);
		log_warn("%s: %s: unlink", a->name, src);
		goto out;
	}
	cleanup_deregister(src);

	res = DELIVER_SUCCESS;
out:
	if (path != NULL)
		xfree(path);
	return (res);
}

void
maildir_desc(struct action *t, char *buf, size_t len)
{
	snprintf(buf, len, "maildir \"%s\"", (char *) t->data);
}
