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

#include <ctype.h> 
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
	int		 	 fd, done;
	long			 code;
	struct io		*io;
	char			*cause, *to, *from, *line, *ptr;
	char			 host[MAXHOSTNAMELEN];
	enum smtp_state		 state;
	size_t		 	 len;

	data = t->data;

	if ((fd = connectto(data->ai, &cause)) < 0) {
		log_warn("%s: %s", a->name, cause);
		return (1);
	}
	io = io_create(fd, NULL, IO_CRLF);
	if (conf.debug > 3)
		io->dup_fd = STDOUT_FILENO;

	if (gethostname(host, sizeof host) != 0)
		fatal("gethostname");
	xasprintf(&from, "%s@%s", conf.user, host);
	if (data->to == NULL)
		to = from;
	else
		to = data->to;

	state = SMTP_CONNECTING;
	for (;;) {
		if (io_poll(io) != 1)
			goto error2;

		done = 0;
		while (!done) {
			line = io_readline(io);
			if (line == NULL)
				break;
			if (isdigit((int) *line)) {
				code = strtol(line, NULL, 10);
				if (code < 100 || code > 999)
					code = -1;
			} else
				code = -1;

			switch (state) {
			case SMTP_CONNECTING:
				if (code != 220)
					goto error;
				state = SMTP_HELO;
				io_writeline(io, "HELO %s", host);
				break;
			case SMTP_HELO:
				if (code != 250)
					goto error;
				state = SMTP_FROM;
				io_writeline(io, "MAIL FROM:%s", from);
				break;
			case SMTP_FROM:
				if (code != 250)
					goto error;
				state = SMTP_TO;
				io_writeline(io, "RCPT TO:%s", to);
				break;
			case SMTP_TO:
				if (code != 250)
					goto error;
				state = SMTP_DATA;
				io_writeline(io, "DATA");
				break;
			case SMTP_DATA:
				if (code != 354)
					goto error;
				line_init(m, &ptr, &len);
				while (ptr != NULL) { 
					/* write without \n */
					io_writeline(io, "%.*s", len - 1, ptr);

					/* update if necessary */
					if (io_update(io) != 1)
						goto error2;

					line_next(m, &ptr, &len);
				}
				state = SMTP_DONE;
				io_writeline(io, ".");
				break;
			case SMTP_DONE:
				if (code != 250)
					goto error;
				state = SMTP_QUIT;
				io_writeline(io, "QUIT");
				break;
			case SMTP_QUIT:
				if (code != 221)
					goto error;
				done = 1;
				break;
			}

			xfree(line);
		}		
		if (done)
			break;
	}

	io_free(io);
	close(fd);

	return (0);

error:
	log_warnx("%s: %s", a->name, line);

error2:
	io_writeline(io, "QUIT");
	io_flush(io);

	io_free(io);
	close(fd);

	return (1);
}
