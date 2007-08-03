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

int	 deliver_mbox_write(FILE *, gzFile, const void *, size_t);

struct deliver deliver_mbox = {
	"mbox",
	DELIVER_ASUSER,
	deliver_mbox_deliver,
	deliver_mbox_desc
};

int
deliver_mbox_write(FILE *f, gzFile gzf, const void *buf, size_t len)
{
	if (gzf == NULL) {
		if (fwrite(buf, len, 1, f) != 1) {
			errno = EIO;
			return (-1);
		}
	} else {
		if ((size_t) gzwrite(gzf, buf, len) != len) {
			errno = EIO;
			return (-1);
		}
	}

	return (0);
}

int
deliver_mbox_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_mbox_data	*data = ti->data;
	char				*path, *ptr, *lptr, *from = NULL;
	const char			*msg;
	size_t	 			 len, llen;
	int	 			 fd;
	FILE				*f;
	gzFile				 gzf;
	long long			 used;
	sigset_t	 		 set, oset;
	struct stat			 sb;

	f = gzf = NULL;
	fd = -1;

	path = replacepath(&data->path, m->tags, m, &m->rml);
	if (path == NULL || *path == '\0') {
		log_warnx("%s: empty path", a->name);
		goto error;
	}
	if (data->compress) {
		len = strlen(path);
		if (len < 3 || strcmp(path + len - 3, ".gz") != 0) {
			path = xrealloc(path, 1, len + 4);
			strlcat(path, ".gz", len + 4);
		}
	}
	log_debug2("%s: saving to mbox %s", a->name, path);

	/* Save the mbox path. */
	add_tag(&m->tags, "mbox_file", "%s", path);

	/* Check permissions and ownership. */
	if (stat(path, &sb) != 0) {
		if (errno != ENOENT)
			goto error_log;
	} else {
		if ((msg = checkmode(&sb, UMASK(FILEMODE))) != NULL)
			log_warnx("%s: %s: %s", a->name, path, msg);
		if ((msg = checkowner(&sb, -1)) != NULL)
			log_warnx("%s: %s: %s", a->name, path, msg);
		if ((msg = checkgroup(&sb, conf.file_group)) != NULL)
			log_warnx("%s: %s: %s", a->name, path, msg);
	}

	/* Create or open the mbox. */
	used = 0;
	do {
		fd = createlock(path, O_WRONLY|O_APPEND,
		    -1, conf.file_group, FILEMODE, conf.lock_types);
		if (fd == -1 && errno == EEXIST)
			fd = openlock(path, O_WRONLY|O_APPEND, conf.lock_types);
		if (fd == -1) {
			if (errno == EAGAIN) {
				if (locksleep(a->name, path, &used) != 0)
					goto error;
				continue;
			}
			goto error_log;
		}
	} while (fd < 0);

	/* Open gzFile or FILE * for writing. */
	if (data->compress) {
		if ((gzf = gzdopen(fd, "a")) == NULL) {
			errno = ENOMEM;
			goto error_log;
		}
	} else {
		if ((f = fdopen(fd, "a")) == NULL)
			goto error_log;
	}

	/*
	 * mboxes are a pain: if we are interrupted after this we risk
	 * having written a partial mail. So, block SIGTERM until we're
	 * done.
	 */
	sigemptyset(&set);
 	sigaddset(&set, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &set, &oset) < 0)
		fatal("sigprocmask failed");

	/* Write the from line. */
	from = make_from(m);
	if (deliver_mbox_write(f, gzf, from, strlen(from)) < 0) {
		xfree(from);
		goto error_unblock;
	}
	if (deliver_mbox_write(f, gzf, "\n", 1) < 0) {
		xfree(from);
		goto error_unblock;
	}
	log_debug3("%s: using from line: %s", a->name, from);
	xfree(from);

	/* Write the mail, escaping from lines. */
	line_init(m, &ptr, &len);
	while (ptr != NULL) {
		if (ptr != m->data) {
			/* Skip leading >s. */
			lptr = ptr;
			llen = len;
			while (*lptr == '>' && llen > 0) {
				lptr++;
				llen--;
			}

			if (llen >= 5 && strncmp(lptr, "From ", 5) == 0) {
				log_debug2("%s: quoting from line: %.*s",
				    a->name, (int) len - 1, ptr);
				if (deliver_mbox_write(f, gzf, ">", 1) < 0)
					goto error_unblock;
			}
		}

		if (deliver_mbox_write(f, gzf, ptr, len) < 0)
			goto error_unblock;

		line_next(m, &ptr, &len);
	}

	/* Append newlines. */
	if (m->data[m->size - 1] == '\n') {
		if (deliver_mbox_write(f, gzf, "\n", 1) < 0)
			goto error_unblock;
	} else {
		if (deliver_mbox_write(f, gzf, "\n\n", 2) < 0)
			goto error_unblock;
	}

	/* Flush buffers and sync. */
	if (gzf == NULL) {
		if (fflush(f) != 0)
			goto error_unblock;
	} else {
		if (gzflush(gzf, Z_FINISH) != Z_OK) {
			errno = EIO;
			goto error_unblock;
		}
	}
	if (fsync(fd) != 0)
		goto error_unblock;

	if (sigprocmask(SIG_SETMASK, &oset, NULL) < 0)
		fatal("sigprocmask failed");

	if (gzf != NULL)
		gzclose(gzf);
	if (f != NULL)
		fclose(f);
	closelock(fd, path, conf.lock_types);

	xfree(path);
	return (DELIVER_SUCCESS);

error_unblock:
	if (sigprocmask(SIG_SETMASK, &oset, NULL) < 0)
		fatal("sigprocmask failed");

error_log:
	log_warn("%s: %s", a->name, path);

error:
	if (gzf != NULL)
		gzclose(gzf);
	if (f != NULL)
		fclose(f);
	if (fd != -1)
		closelock(fd, path, conf.lock_types);

	if (path != NULL)
		xfree(path);
	return (DELIVER_FAILURE);
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
