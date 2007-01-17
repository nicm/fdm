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

int	 smtp_deliver(struct deliver_ctx *, struct action *);
char	*smtp_desc(struct action *);

int	 smtp_code(char *);

struct deliver deliver_smtp = { DELIVER_ASUSER, smtp_deliver, smtp_desc };

int
smtp_code(char *line)
{
	char		 ch;
	const char	*errstr;
	int	 	 n;
	size_t		 len;

	len = strspn(line, "0123456789");
	if (len == 0)
		return (-1);
	ch = line[len];
	line[len] = '\0';

	n = strtonum(line, 100, 999, &errstr);
	line[len] = ch;
	if (errstr != NULL)
		return (-1);

	return (n);
}

int
smtp_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct account		*a = dctx->account;
	struct mail		*m = dctx->mail;
	struct smtp_data	*data = t->data;
	int		 	 done, code;
	struct io		*io;
	char			*cause, *to, *from, *line, *ptr, *lbuf;
	enum smtp_state		 state;
	size_t		 	 len, llen;

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

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	state = SMTP_CONNECTING;
	line = cause = NULL;
	done = 0;
	do {
		switch (io_pollline2(io, &line, &lbuf, &llen, &cause)) {
		case 0:
			cause = xstrdup("connection unexpectedly closed");
			break;
		case -1:
			goto error;
		}
		code = smtp_code(line);
		
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
			io_flush(io, NULL);
			break;
		case SMTP_DONE:
			if (code != 250)
				goto error;
			state = SMTP_QUIT;
			io_writeline(io, "QUIT");
			break;
		case SMTP_QUIT:
			/* 
			 * Exchange sometimes refuses to accept QUIT as a valid
			 * command, but since we got a 250 the mail has been
			 * accepted. So, allow 500 here too.
			 */
			if (code != 500 && code != 221)
				goto error;
			done = 1;
			break;
		}
	} while (!done);

	xfree(lbuf);	
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
	
	xfree(lbuf);
	xfree(from);

	io_close(io);
	io_free(io);

	return (DELIVER_FAILURE);
}

char *
smtp_desc(struct action *t)
{
	struct smtp_data	*data = t->data;
	char			*s;

	xasprintf(&s, "smtp%s server \"%s\" port %s to \"%s\"",
	    data->server.ssl ? "s" : "", data->server.host, data->server.port,
	    data->to);
	return (s);
}
