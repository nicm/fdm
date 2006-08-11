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

u_int	maildir_deliveries;

int	maildir_deliver(struct account *, struct action *, struct mail *);

struct deliver deliver_maildir = { "maildir", maildir_deliver };

int
maildir_deliver(unused struct account *a, unused struct action *t, 
    unused struct mail *m) 
{
	char	*path, *map[REPL_LEN], ch;
	char	 host1[MAXHOSTNAMELEN], host2[MAXHOSTNAMELEN], *host;
	char	 name[MAXPATHLEN], src[MAXPATHLEN], dst[MAXPATHLEN];
	int	 fd;
	ssize_t	 n;
	size_t	 first, last;

	bzero(map, sizeof map);
	map[REPL_IDX('a')] = a->name;
	map[REPL_IDX('h')] = conf.home;
	map[REPL_IDX('t')] = t->name;
	path = replace(t->data, map);

	if (path == NULL || *((char *) path) == '\0') {
		log_warnx("%s: empty path", a->name);
		goto error;
	}

	/* create the maildir directories */
	if (mkdir(path, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, path);
		goto error;
	}
	if (xsnprintf(name, sizeof name, "%s/cur", path) < 0) {
		log_warn("%s: %s: xsnprintf", a->name, path);
		goto error;
	}
	if (mkdir(name, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, name);
		goto error;
	}
	if (xsnprintf(name, sizeof name, "%s/new", path) < 0) {
		log_warn("%s: %s: xsnprintf", a->name, path);
		goto error;
	}
	if (mkdir(name, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, name);
		goto error;
	}	
	if (xsnprintf(name, sizeof name, "%s/tmp", path) < 0) {
		log_warn("%s: %s: xsnprintf", a->name, path);
		goto error;
	}
	if (mkdir(name, S_IRWXU) != 0 && errno != EEXIST) {
		log_warn("%s: %s: mkdir", a->name, name);
		goto error;
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
		if (xsnprintf(name, sizeof name, "%llu.%llu_%u.%s", 
		    (unsigned long long) time(NULL), 
		    (unsigned long long) getpid(), 
		    maildir_deliveries, host) < 0) {
			log_warn("%s: %s: xsnprintf", a->name, path);
			goto error;
		}
		
		if (xsnprintf(src, sizeof src, "%s/tmp/%s", path, name) < 0) {
			log_warn("%s: %s: xsnprintf", a->name, path);
			goto error;
		}		
	
		fd = open(src, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
		if (fd == -1 && errno != EEXIST) {
			log_warn("%s: open(\"%s\")", a->name, src);
			goto error;
		}

		maildir_deliveries++;
	} while (fd == -1);

	/* write the message */
	log_debug("%s: writing to %s", a->name, src);
	n = write(fd, m->data, m->size);
	if (n < 0 || (size_t) n != m->size) {
		log_warn("%s: write", a->name);
		close(fd);
		unlink(src);
		if (n != -1)
			errno = EIO;
		goto error;
	}
	close(fd);

	/* create the new path and attempt to link it. a failed link jumps
	   back to find another name in the tmp directory */
	if (xsnprintf(dst, sizeof dst, "%s/new/%s", path, name) < 0) {
		log_warn("%s: %s: xsnprintf", a->name, path);
		goto error;
	}		
	log_debug("%s: linking .../%s to .../%s", a->name, 
	    src + strlen(path) + 1, dst + strlen(path) + 1);
	if (link(src, dst) != 0) {
		unlink(src);
		if (errno == EEXIST) {
			log_debug("%s: link failed", a->name);
			goto restart;
		}
		log_warn("%s: link(\"%s, %s\")", a->name, src, dst);
		goto error;
	}

	/* unlink the original tmp file */
	log_debug("%s: unlinking .../%s", a->name, src + strlen(path) + 1);
	if (unlink(src) != 0) {
		log_warn("%s: unlink(\"%s\")", a->name, src);
		goto error;
	}

	xfree(path);
	return (0);

error:
	if (path != NULL)
		xfree(path);
	return (1);
}
