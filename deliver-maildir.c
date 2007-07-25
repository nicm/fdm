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

int	 deliver_maildir_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_maildir_desc(struct actitem *, char *, size_t);

char 	*deliver_maildir_host(void);
int	 deliver_maildir_create(struct account *, const char *);

struct deliver deliver_maildir = {
	"maildir",
	DELIVER_ASUSER,
	deliver_maildir_deliver,
	deliver_maildir_desc
};

/*
 * Return hostname with '/' replaced with "\057" and ':' with "\072". This is a
 * bit inefficient but sod it. Why they couldn't both be replaced by _ is
 * beyond me...
 *
 * The hostname will be truncated if these additions make it longer than
 * MAXHOSTNAMELEN. No clue if this is right.
 */
char *
deliver_maildir_host(void)
{
	static char	host1[MAXHOSTNAMELEN], host2[MAXHOSTNAMELEN];
	char		ch;
	size_t		first, last;

	if (gethostname(host1, sizeof host1) != 0)
		fatal("gethostname failed");
	*host2 = '\0';

	last = strcspn(host1, "/:");
	if (host1[last] == '\0')
		return (host1);

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

		first += last + 1;
		last = strcspn(host1 + first, "/:");
	} while (ch != '\0');

	return (host2);
}

/* Create a new maildir. */
int
deliver_maildir_create(struct account *a, const char *maildir)
{
	struct stat	sb;
	const char     *msg, *names[] = { "", "/cur", "/new", "/tmp", NULL };
	char		path[MAXPATHLEN];
	u_int		i;

	for (i = 0; names[i] != NULL; i++) {
		if (mkpath(path, sizeof path, "%s%s", maildir, names[i]) != 0)
			goto error;
		log_debug("%s: creating %s", a->name, path);

		if (xmkdir(path, -1, conf.file_group, DIRMODE) == 0)
			continue;
		if (errno != EEXIST)
			goto error;

		if (stat(path, &sb) != 0)
			goto error;
		if ((msg = checkmode(&sb, UMASK(DIRMODE))) != NULL)
			log_warnx("%s: %s: %s", a->name, path, msg);
		if ((msg = checkowner(&sb, -1)) != NULL)
			log_warnx("%s: %s: %s", a->name, path, msg);
		if ((msg = checkgroup(&sb, conf.file_group)) != NULL)
			log_warnx("%s: %s: %s", a->name, path, msg);
	}

	return (0);

error:
	log_warn("%s: %s%s", a->name, path, names[i]);
	return (-1);
}

int
deliver_maildir_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_maildir_data	*data = ti->data;
	static u_int			 delivered = 0;
	char				*host, *name, *path;
	char				 src[MAXPATHLEN], dst[MAXPATHLEN];
	int	 			 fd;
	ssize_t			 	 n;

	name = NULL;
	fd = -1;

	path = replacepath(&data->path, m->tags, m, &m->rml);
	if (path == NULL || *path == '\0') {
		log_warnx("%s: empty path", a->name);
		goto error;
	}
	log_debug2("%s: saving to maildir %s", a->name, path);

	/* Create the maildir. */
	if (deliver_maildir_create(a, path) != 0)
		goto error;

	/* Find host name. */
	host = deliver_maildir_host();

restart:
	/* Find a suitable name in tmp. */
	do {
		if (name != NULL)
			xfree(name);
 		xasprintf(&name, "%ld.%ld_%u.%s",
		    (long) time(NULL), (long) getpid(), delivered, host);

		if (mkpath(src, sizeof src, "%s/tmp/%s", path, name) != 0) {
			log_warn("%s: %s/tmp/%s", a->name, path, name);
			goto error;
		}
		log_debug3("%s: trying %s/tmp/%s", a->name, path, name);

		fd = xcreate(src, O_WRONLY, -1, conf.file_group, FILEMODE);
		if (fd == -1 && errno != EEXIST)
			goto error_log;

		delivered++;
	} while (fd == -1);
	cleanup_register(src);

	/* Write the message. */
	log_debug2("%s: writing to %s", a->name, src);
	n = write(fd, m->data, m->size);
	if (n < 0 || (size_t) n != m->size || fsync(fd) != 0)
		goto error_unlink;
	close(fd);
	fd = -1;

	/*
	 * Create the new path and attempt to link it. A failed link jumps
	 * back to find another name in the tmp directory.
	 */
	if (mkpath(dst, sizeof dst, "%s/new/%s", path, name) != 0)
		goto error_unlink;
	log_debug2(
	    "%s: linking .../tmp/%s to .../new/%s", a->name, name, name);
	if (link(src, dst) != 0) {
		if (errno == EEXIST) {
			log_debug2("%s: %s: link failed", a->name, src);
			if (unlink(src) != 0)
				fatal("unlink failed");
			cleanup_deregister(src);
			goto restart;
		}
		goto error_unlink;
	}

	/* Unlink the original tmp file. */
	log_debug2("%s: unlinking .../tmp/%s", a->name, name);
	if (unlink(src) != 0)
		goto error_unlink;
	cleanup_deregister(src);

	/* Save the mail file as a tag. */
	add_tag(&m->tags, "mail_file", "%s", dst);

	xfree(name);
	xfree(path);
	return (DELIVER_SUCCESS);

error_unlink:
	if (unlink(src) != 0)
		fatal("unlink failed");
	cleanup_deregister(src);

error_log:
	log_warn("%s: %s", a->name, src);

error:
	if (fd != -1)
		close(fd);

	if (name != NULL)
		xfree(name);
	if (path != NULL)
		xfree(path);
	return (DELIVER_FAILURE);
}

void
deliver_maildir_desc(struct actitem *ti, char *buf, size_t len)
{
	struct deliver_maildir_data	*data = ti->data;

	xsnprintf(buf, len, "maildir \"%s\"", data->path.str);
}
