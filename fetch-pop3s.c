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
 
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	pop3s_connect(struct account *);
int	pop3s_disconnect(struct account *);

struct fetch	fetch_pop3s = { "pop3s", "pop3s",
				pop3s_connect, 
				pop3_poll, /* from fetch-pop3.c */
				pop3_fetch, /* from fetch-pop3.c */
				pop3s_disconnect };

int
pop3s_connect(struct account *a)
{
	struct pop3_data	*data;
	SSL		        *ssl;
	char			*cause;
	int			 n;

	data = a->data;

	if ((data->fd = connectto(data->ai, &cause)) < 0) {
		log_warn("%s: %s", a->name, cause);
		return (1);
	}

	data->ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(data->ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(data->ctx);
	if (ssl == NULL) {
		log_warnx("%s: SSL_new: %s", a->name, ssl_err());
		return (1);
	}
	if (SSL_set_fd(ssl, data->fd) != 1) {
		log_warnx("%s: SSL_set_fd: %s", a->name, ssl_err());
		return (1);
	}
	SSL_set_connect_state(ssl);
	if ((n = SSL_connect(ssl)) < 1) {
		n = SSL_get_error(ssl, n);
		log_warnx("%s: SSL_connect: %d", a->name, n);
		return (1);
	}

	data->io = io_create(data->fd, ssl, IO_CRLF);
	if (conf.debug > 2)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = POP3_CONNECTING;

	return (0);
}

int
pop3s_disconnect(struct account *a)
{
	struct pop3_data	*data;

	data = a->data;

	SSL_free(data->io->ssl);
	SSL_CTX_free(data->ctx);
	io_free(data->io);

	close(data->fd);

	return (0);
}
