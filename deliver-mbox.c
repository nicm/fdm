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
#include "deliver.h"

/* With gcc 2.95.x, you can't include zlib.h before openssl.h. */
#include <zlib.h>

int	 deliver_mbox_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_mbox_desc(struct actitem *, char *, size_t);

int	 deliver_mbox_write(int, gzFile, const void *, size_t);

struct deliver deliver_mbox = {
	"mbox",
	DELIVER_ASUSER,
	deliver_mbox_deliver,
	deliver_mbox_desc
};

int
deliver_mbox_write(int fd, gzFile gzf, const void *buf, size_t len)
{
	ssize_t	n;

	if (gzf == NULL)
		n = write(fd, buf, len);
	else
		n = gzwrite(gzf, buf, len);

	if (n < 0)
		return (-1);
	if ((size_t) n != len) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

int
deliver_mbox_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_mbox_data	*data = ti->data;
	char				*path, *ptr, *ptr2, *from = NULL;
	size_t	 			 len, len2;
	int	 			 exists, fd = -1, fd2;
	int				 res = DELIVER_FAILURE;
	gzFile				 gzf = NULL;
	u_int				 n;
	sigset_t	 		 set, oset;

	path = replacepath(&data->path, m->tags, m, &m->rml);
	if (path == NULL || *path == '\0') {
		if (path != NULL)
			xfree(path);
		log_warnx("%s: empty path", a->name);
		goto out;
	}
	if (data->compress) {
		len = strlen(path);
		if (len < 3 || strcmp(path + len - 3, ".gz") != 0) {
			xasprintf(&ptr, "%s.gz", path);
			xfree(path);
			path = ptr;
		}
	}
	log_debug2("%s: saving to mbox %s", a->name, path);

	/* save the mbox path */
	add_tag(&m->tags, "mbox_file", "%s", path);

	/* create a from line for the mail */
	from = make_from(m);
	log_debug3("%s: using from line: %s", a->name, from);

	/* check permissions and ownership */
	if (checkperms(a->name, path, &exists) != 0) {
		log_warn("%s: %s: checkperms", a->name, path);
		goto out;
	}

	n = 0;
	do {
		fd = openlock(path, conf.lock_types, O_CREAT|O_WRONLY|O_APPEND,
		    FILEMODE);
		if (fd < 0) {
			if (errno == EAGAIN) {
				usleep(LOCKSLEEPTIME);
				n++;
				if (n >= LOCKRETRIES) {
					log_warnx("%s: %s: couldn't obtain lock"
					    " in %.2f seconds", a->name, path,
					    (LOCKSLEEPTIME * n) / 1000000.0);
					goto out;
				}
			} else {
				log_warn("%s: %s: open", a->name, path);
				goto out;
			}
		}
	} while (fd < 0);
	if (!exists && conf.file_group != NOGRP) {
		if (fchown(fd, -1, conf.file_group) == -1) {
			log_warn("%s: %s: fchown", a->name, path);
			goto out;
		}
	}

	/* open for compressed writing if necessary */
	if (data->compress) {
		if ((fd2 = dup(fd)) < 0)
			fatal("dup");
		errno = 0;
		if ((gzf = gzdopen(fd2, "a")) == NULL) {
			if (errno == 0)
				errno = ENOMEM;
			close(fd2);
			log_warn("%s: %s: gzdopen", a->name, path);
			goto out;
		}
	}

	/*
	 * mboxes are a pain: if we are interrupted after this we risk
	 * having written a partial mail. So, block SIGTERM until we're
	 * done.
	 */
 	sigaddset(&set, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &set, &oset) < 0)
		fatal("sigprocmask");

	/* write the from line */
	if (deliver_mbox_write(fd, gzf, from, strlen(from)) < 0) {
		log_warn("%s: %s: write", a->name, path);
		goto out2;
	}
	if (deliver_mbox_write(fd, gzf, "\n", 1) < 0) {
		log_warn("%s: %s: write", a->name, path);
		goto out2;
	}

	/* write the mail */
	line_init(m, &ptr, &len);
	while (ptr != NULL) {
		if (ptr != m->data) {
			/* skip >s */
			ptr2 = ptr;
			len2 = len;
			while (*ptr2 == '>' && len2 > 0) {
				ptr2++;
				len2--;
			}
			if (len2 >= 5 && strncmp(ptr2, "From ", 5) == 0) {
				log_debug2("%s: quoting from line: %.*s",
				    a->name, (int) len - 1, ptr);
				if (deliver_mbox_write(fd, gzf, ">", 1) < 0) {
					log_warn("%s: %s: write", a->name,
					    path);
					goto out2;
				}
			}
		}

		if (deliver_mbox_write(fd, gzf, ptr, len) < 0) {
			log_warn("%s: %s: write", a->name, path);
			goto out2;
		}

		line_next(m, &ptr, &len);
	}
	len = m->data[m->size - 1] == '\n' ? 1 : 2;
	if (deliver_mbox_write(fd, gzf, "\n\n", len) < 0) {
		log_warn("%s: %s: write", a->name, path);
		goto out2;
	}

	if (fsync(fd) != 0) {
		log_warn("%s: %s: fsync", a->name, path);
		goto out2;
	}

	res = DELIVER_SUCCESS;

out2:
	if (sigprocmask(SIG_SETMASK, &oset, NULL) < 0)
		fatal("sigprocmask");

out:
	if (gzf != NULL)
		gzclose(gzf);
	if (fd != -1)
		closelock(fd, path, conf.lock_types);
	if (from != NULL)
		xfree(from);
	if (path != NULL)
		xfree(path);
	return (res);
}

void
deliver_mbox_desc(struct actitem *ti, char *buf, size_t len)
{
	struct deliver_mbox_data	*data = ti->data;

	if (data->compress)
		xsnprintf(buf, len, "mbox \"%s\" compress", data->path.str);
	else
		xsnprintf(buf, len, "mbox \"%s\"", data->path.str);
}
