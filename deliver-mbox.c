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
	char	*path, *map[REPL_LEN], *line, *ptr;
	int	 fd = -1, error = 0;

	bzero(map, sizeof map);
	map[REPL_IDX('a')] = a->name;
	map[REPL_IDX('h')] = conf.home;
	map[REPL_IDX('t')] = t->name;
	map[REPL_IDX('u')] = conf.user;
	path = replace(t->data, map);
	if (path == NULL || *path == '\0') {
		log_warnx("%s: empty path", a->name);
		goto out;
	}
	log_debug("%s: saving to mbox %s", a->name, path); 

	/* ensure an existing from line is available */
	if (m->from == NULL)
		make_from(m);

	/* XXX dest file sanity checks: ownership? */
	do {
		fd = openlock(path, conf.lock_types, 
		    O_CREAT|O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR);
		if (fd == -1) {
			if (errno == EAGAIN) {
				log_warnx("%s: %s: couldn't obtain lock. "
				    "sleeping", a->name, path);
				sleep(LOCKSLEEPTIME);
			} else {
				log_warn("%s: open(\"%s\")", a->name, path);
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
	line = m->data;
	do {
		ptr = memchr(line, '\n', m->size);
		if (ptr == NULL)
			ptr = m->data + m->size;
		
		if (line != m->data &&
		    ptr - line >= 5 && strncmp(line, "From ", 5) == 0) {
			if (write(fd, ">", 1) == -1) {
				log_warn("%s: %s: write", a->name, path);
				error = 1;
				goto out;
			}
		}

		if (write(fd, line, ptr - line + 1) == -1) {
			log_warn("%s: %s: write", a->name, path);
			error = 1;
			goto out;
		}
		
		line = ptr + 1;
	} while (line != m->data + m->size);

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
