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
 
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	smtp_deliver(struct account *, struct action *, struct mail *);

struct deliver deliver_smtp = { "smtp", smtp_deliver };

int
smtp_deliver(struct account *a, struct action *t, struct mail *m) 
{
	struct smtp_data	*data;
	int		 	 fd;
	struct io		*io;
	char			*cause, *to;
	char			 host[MAXHOSTNAMELEN];

	fatalx("smtp_deliver: not yet implemented");

	data = t->data;

	if (data->to == NULL) {
		if (gethostname(host, sizeof host) != 0)
			fatal("gethostname");
		xasprintf(&to, "%s@%s", host, conf.user);
	} else
		to = data->to;

	if ((fd = connectto(t->data, &cause)) < 0) {
		log_warn("%s: %s", a->name, cause);
		return (1);
	}
	io = io_create(fd, NULL, IO_CRLF);
	if (conf.debug > 3)
		io->dup_fd = STDOUT_FILENO;
	
	for (;;) {
		if (io_poll(io) != 1)
			goto error;

		/** **/
	}

	io_free(io);
	close(fd);

	return (0);

error:
	io_writeline(io, "QUIT");
	io_flush(io);

	io_free(io);
	close(fd);

	return (1);
}
