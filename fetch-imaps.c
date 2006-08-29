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

int	imaps_connect(struct account *);
int	imaps_disconnect(struct account *);

struct fetch	fetch_imaps = { "imaps", "imaps",
				imaps_connect, 
				imap_poll,	/* from fetch-imap.c */
				imap_fetch, 	/* from fetch-imap.c */
				imap_delete, 	/* from fetch-imap.c */
				imap_error, 	/* from fetch-imap.c */
				imaps_disconnect };

int
imaps_connect(struct account *a)
{
	struct imap_data	*data;
	SSL		        *ssl;
	char			*cause;
	int			 n;

	data = a->data;

	if ((data->fd = connectto(&data->server, &cause)) < 0) {
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	data->ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(data->ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(data->ctx);
	if (ssl == NULL) {
		log_warnx("%s: SSL_new: %s", a->name, SSL_err());
		return (1);
	}
	if (SSL_set_fd(ssl, data->fd) != 1) {
		log_warnx("%s: SSL_set_fd: %s", a->name, SSL_err());
		return (1);
	}
	SSL_set_connect_state(ssl);
	if ((n = SSL_connect(ssl)) < 1) {
		n = SSL_get_error(ssl, n);
		log_warnx("%s: SSL_connect: %d", a->name, n);
		return (1);
	}

	data->io = io_create(data->fd, ssl, IO_CRLF);
	if (conf.debug > 3)
		data->io->dup_fd = STDOUT_FILENO;

	data->state = IMAP_CONNECTING;
	data->tag = 0;

	return (0);
}

int
imaps_disconnect(struct account *a)
{
	struct imap_data	*data;

	data = a->data;

	SSL_free(data->io->ssl);
	SSL_CTX_free(data->ctx);
	io_free(data->io);

	close(data->fd);

	return (0);
}
