/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicholas.marriott@gmail.com>
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

void	fetch_stdin_abort(struct account *);
u_int	fetch_stdin_total(struct account *);
void	fetch_stdin_desc(struct account *, char *, size_t);

int	fetch_stdin_state_init(struct account *, struct fetch_ctx *);
int	fetch_stdin_state_mail(struct account *, struct fetch_ctx *);
int	fetch_stdin_state_exit(struct account *, struct fetch_ctx *);

struct fetch fetch_stdin = {
	"stdin",
	fetch_stdin_state_init,

	NULL,
	NULL,
	fetch_stdin_abort,
	NULL,
	fetch_stdin_desc
};

/* Abort; close stdin. */
void
fetch_stdin_abort(unused struct account *a)
{
	close(STDIN_FILENO);
}

/* Initialise stdin fetch. */
int
fetch_stdin_state_init(struct account *a, struct fetch_ctx *fctx)
{
	/* Check stdin is valid. */
	if (isatty(STDIN_FILENO)) {
		log_warnx("%s: stdin is a tty. ignoring", a->name);
		return (FETCH_ERROR);
	}
	if (fcntl(STDIN_FILENO, F_GETFL) == -1) {
		if (errno != EBADF)
			fatal("fcntl failed");
		log_warnx("%s: stdin is invalid", a->name);
		return (FETCH_ERROR);
	}

	fctx->state = fetch_stdin_state_mail;
	return (FETCH_AGAIN);
}

/* Fetch mail from stdin. */
int
fetch_stdin_state_mail(struct account *a, struct fetch_ctx *fctx)
{
	struct mail	*m = fctx->mail;
	struct io	*io;
	char		*line, *cause;

	/* Open io for stdin. */
	io = io_create(STDIN_FILENO, NULL, IO_LF);
	if (conf.debug > 3 && !conf.syslog)
		io->dup_fd = STDOUT_FILENO;

	/* Initialise the mail. */
	if (mail_open(m, IO_BLOCKSIZE) != 0) {
		log_warn("%s: failed to create mail", a->name);
		goto error;
	}
	m->size = 0;

	/* Add default tags. */
	default_tags(&m->tags, NULL);

	/* Loop reading the mail. */
	for (;;) {
		/*
		 * There can only be one mail on stdin so reentrancy is
		 * irrelevent. This is a good thing since we want to check for
		 * close which means end of mail.
		 */
		switch (io_pollline2(io,
		    &line, &fctx->lbuf, &fctx->llen, conf.timeout, &cause)) {
		case 0:
			/* Normal close is fine. */
			goto out;
		case -1:
			if (errno == EAGAIN)
				continue;
			log_warnx("%s: %s", a->name, cause);
			xfree(cause);
			goto error;
		}

		if (append_line(m, line, strlen(line)) != 0) {
			log_warn("%s: failed to resize mail", a->name);
			goto error;
		}
		if (m->size > conf.max_size)
			break;
	}

out:
	if (io != NULL)
		io_free(io);

	fctx->state = fetch_stdin_state_exit;
	return (FETCH_MAIL);


error:
	if (io != NULL)
		io_free(io);

	return (FETCH_ERROR);
}

/* Fetch finished; return exit. */
int
fetch_stdin_state_exit(unused struct account *a, unused struct fetch_ctx *fctx)
{
	close(STDIN_FILENO);
	return (FETCH_EXIT);
}

void
fetch_stdin_desc(unused struct account *a, char *buf, size_t len)
{
	strlcpy(buf, "stdin", len);
}
