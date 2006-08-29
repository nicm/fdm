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

int	mbox_deliver(struct account *, struct action *, struct mail *);

struct deliver deliver_mbox = { "mbox", mbox_deliver };

int
mbox_deliver(struct account *a, struct action *t, struct mail *m) 
{
	char		*path, *ptr;
	size_t	 	 len;
	int	 	 fd = -1, error = 0;
	struct stat	 sb;

	path = replaceinfo(t->data, a, t);
	if (path == NULL || *path == '\0') {
		log_warnx("%s: empty path", a->name);
		goto out;
	}
	log_debug("%s: saving to mbox %s", a->name, path); 

	/* check permissions and ownership */
	errno = 0;
	if (stat(path, &sb) != 0 && errno != ENOENT) {
		log_warn("%s: %s: stat", a->name, path);
		error = 1;
		goto out;
	} else if (errno == 0) {
		if ((sb.st_mode & (S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|
		    S_IROTH|S_IWOTH|S_IXOTH)) != 0) {
			log_warnx("%s: %s: bad permissions: %o%o%o, "
			    "should be 600", a->name, path,
			    (sb.st_mode & S_IRUSR ? 4 : 0) +
			    (sb.st_mode & S_IWUSR ? 2 : 0) +
			    (sb.st_mode & S_IXUSR ? 1 : 0),
			    (sb.st_mode & S_IRGRP ? 4 : 0) +
			    (sb.st_mode & S_IWGRP ? 2 : 0) +
			    (sb.st_mode & S_IXGRP ? 1 : 0),
			    (sb.st_mode & S_IROTH ? 4 : 0) +
			    (sb.st_mode & S_IWOTH ? 2 : 0) +
			    (sb.st_mode & S_IXOTH ? 1 : 0));
			error = 1;
			goto out;
		}
		if (sb.st_uid != getuid()) {
			log_warnx("%s: %s: bad owner: %lu, should be %lu", 
			    a->name, path, 
			    (u_long) sb.st_uid, (u_long) getuid());
			error = 1;
			goto out;
		}
	}

	/* ensure an existing from line is available */
	if (m->from == NULL)
		make_from(m);

	do {
		fd = openlock(path, conf.lock_types, 
		    O_CREAT|O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR);
		if (fd == -1) {
			if (errno == EAGAIN) {
				log_warnx("%s: %s: couldn't obtain lock. "
				    "sleeping", a->name, path);
				sleep(LOCKSLEEPTIME);
			} else {
				log_warn("%s: %s: open", a->name, path);
				error = 1;
				goto out;
			}
		}
	} while (fd == -1);

	/* write the from line */
	if (write(fd, m->from, strlen(m->from)) == -1) {
		log_warn("%s: %s: write", a->name, path);
		error = 1;
		goto out;
	}

	/* write the mail */
	line_init(m, &ptr, &len);
	while (ptr != NULL) {
		if (ptr != m->data && 
		    len >= 5 && strncmp(ptr, "From ", 5) == 0) {
			if (write(fd, ">", 1) == -1) {
				log_warn("%s: %s: write", a->name, path);
				error = 1;
				goto out;
			}
		}

		if (write(fd, ptr, len) == -1) {
			log_warn("%s: %s: write", a->name, path);
			error = 1;
			goto out;
		}
		
		line_next(m, &ptr, &len);
	}
	
	if (write(fd, "\n\n", 2) == -1) {
		log_warn("%s: %s: write", a->name, path);
		error = 1;
		goto out;
	}

out:
	if (fd != -1)
		closelock(fd, path, conf.lock_types);
	if (path != NULL)
		xfree(path);
	return (error);
}
