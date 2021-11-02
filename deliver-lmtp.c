/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicholas.marriott@gmail.com>
 * Copyright (c) 2021 Anonymous
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
#include "deliver.h"

int	 deliver_lmtp_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_lmtp_desc(struct actitem *, char *, size_t);

int	 deliver_lmtp_code(char *);

enum deliver_lmtp_state {
	LMTP_CONNECTING,
	LMTP_LHLO,
	LMTP_FROM,
	LMTP_TO,
	LMTP_DATA,
	LMTP_DONE,
	LMTP_QUIT
};

struct deliver deliver_lmtp = {
	"lmtp",
	DELIVER_ASUSER,
	deliver_lmtp_deliver,
	deliver_lmtp_desc
};

int
deliver_lmtp_code(char *line)
{
	char		 ch;
	const char	*errstr;
	int		 n;
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
deliver_lmtp_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_lmtp_data	*data = ti->data;
	int				 done, code;
	struct io			*io;
	char				*cause = NULL, *to, *from, *line, *ptr;
	char				*lbuf;
	enum deliver_lmtp_state		 state;
	size_t				 len, llen;

	if (data->socket != NULL)
		io = connectunix(data->socket, &cause);
	else {
		io = connectio(&data->server, conf.verify_certs, IO_CRLF,
		    conf.timeout, &cause);
	}

	if (io == NULL) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (DELIVER_FAILURE);
	}

	if (conf.debug > 3 && !conf.syslog)
		io->dup_fd = STDOUT_FILENO;


	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	if (conf.host_fqdn != NULL)
		xasprintf(&ptr, "%s@%s", dctx->udata->name, conf.host_fqdn);
	else
		xasprintf(&ptr, "%s@%s", dctx->udata->name, conf.host_name);
	if (data->to.str == NULL)
		to = xstrdup(ptr);
	else {
		to = replacestr(&data->to, m->tags, m, &m->rml);
		if (to == NULL || *to == '\0') {
			xasprintf(&cause, "%s: empty to", a->name);
			from = NULL;
			goto error;
		}
	}
	if (data->from.str == NULL)
		from = xstrdup(ptr);
	else {
		from = replacestr(&data->from, m->tags, m, &m->rml);
		if (from == NULL || *from == '\0') {
			xasprintf(&cause, "%s: empty from", a->name);
			goto error;
		}
	}
	xfree(ptr);

	state = LMTP_CONNECTING;
	done = 0;
	do {
		switch (io_pollline2(io, &line, &lbuf, &llen, conf.timeout,
		    &cause)) {
		case 0:
			cause = xstrdup("connection unexpectedly closed");
			goto error;
		case -1:
			goto error;
		}
		code = deliver_lmtp_code(line);

		switch (state) {
		case LMTP_CONNECTING:
			if (code != 220)
				goto error;

			state = LMTP_LHLO;
			if (conf.host_fqdn != NULL)
				io_writeline(io, "LHLO %s", conf.host_fqdn);
			else
				io_writeline(io, "LHLO %s", conf.host_name);
			break;
		case LMTP_LHLO:
			if (code != 250)
				goto error;

			if (line[3] == ' ') {
				state = LMTP_FROM;
				io_writeline(io, "MAIL FROM:<%s>", from);
			}
			break;
		case LMTP_FROM:
			if (code != 250)
				goto error;
			state = LMTP_TO;
			io_writeline(io, "RCPT TO:<%s>", to);
			break;
		case LMTP_TO:
			if (code != 250)
				goto error;
			state = LMTP_DATA;
			io_writeline(io, "DATA");
			break;
		case LMTP_DATA:
			if (code != 354)
				goto error;
			line_init(m, &ptr, &len);
			while (ptr != NULL) {
				if (len > 1) {
					if (*ptr == '.')
						io_write(io, ".", 1);
					io_write(io, ptr, len - 1);
				}
				io_writeline(io, NULL);

				/* Update if necessary. */
				if (io_update(io, conf.timeout, &cause) != 1)
					goto error;

				line_next(m, &ptr, &len);
			}
			state = LMTP_DONE;
			io_writeline(io, ".");
			io_flush(io, conf.timeout, NULL);
			break;
		case LMTP_DONE:
			if (code != 250)
				goto error;
			state = LMTP_QUIT;
			io_writeline(io, "QUIT");
			break;
		case LMTP_QUIT:
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
	xfree(to);

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
	io_flush(io, conf.timeout, NULL);

	xfree(lbuf);
	if (from != NULL)
		xfree(from);
	if (to != NULL)
		xfree(to);

	io_close(io);
	io_free(io);

	return (DELIVER_FAILURE);
}

void
deliver_lmtp_desc(struct actitem *ti, char *buf, size_t len)
{
	struct deliver_lmtp_data	*data = ti->data;

	if (data->socket != NULL) {
		xsnprintf(buf, len, "lmtp-unix \"%s\" to \"%s\"",
		    data->socket, data->to.str);
	} else {
		xsnprintf(buf, len, "lmtp-inet \"%s\" port \"%s\" to \"%s\"",
		    data->server.host, data->server.port, data->to.str);
	}
}

