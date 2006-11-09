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
	int		 	 done;
	long			 code;
	struct io		*io;
	char			*cause, *to, *from, *line, *ptr;
	const char		*errstr;
	enum smtp_state		 state;
	size_t		 	 len;

	data = t->data;

	io = connectproxy(&data->server, conf.proxy, IO_CRLF, &cause);
	if (io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (DELIVER_FAILURE);
	}
	if (conf.debug > 3 && !conf.syslog)
		io->dup_fd = STDOUT_FILENO;

	xasprintf(&from, "%s@%s", conf.info.user, conf.info.host);
	if (data->to == NULL)
		to = from;
	else
		to = data->to;

	state = SMTP_CONNECTING;
	line = cause = NULL;
	for (;;) {
		switch (io_poll(io, &cause)) {
		case -1:
			goto error;
		case 0:
			cause = xstrdup("connection unexpectedly closed");
			goto error;
		}

		done = 0;
		while (!done) {
			line = io_readline(io);
			if (line == NULL)
				break;
			if (isdigit((int) *line)) {
				code = strtonum(line, 100, 999, &errstr);
				if (errstr != NULL)
					code = -1;
			} else
				code = -1;

			switch (state) {
			case SMTP_CONNECTING:
				if (code != 220)
					goto error;
				state = SMTP_HELO;
				io_writeline(io, "HELO %s", conf.info.host);
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
					io_write(io, ptr, len - 1);
					io_writeline(io, NULL);

					/* update if necessary */
					if (io_update(io, &cause) != 1)
						goto error;

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

	xfree(from);

	io_close(io);
	io_free(io);

	return (DELIVER_SUCCESS);

error:
	if (cause != NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
	} else
		log_warnx("%s: unexpected response: %s", a->name, line);

	io_writeline(io, "QUIT");
	io_flush(io, NULL);

	xfree(from);

	io_close(io);
	io_free(io);

	return (DELIVER_FAILURE);
}
