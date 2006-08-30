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
#include <sys/socket.h> 

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "fdm.h"

struct proxy *
getproxy(char *url)
{
	struct proxy	*pr;
	char		*ptr;

	pr = xmalloc(sizeof *pr);
	pr->server.ai = NULL;

	if (strncmp(url, "http://", 7) == 0) {
		pr->type = PROXY_HTTP;
		url += 7;
	} else if (strncmp(url, "https://", 8) == 0) {
		pr->type = PROXY_HTTPS;
		url += 9;
	} else
		return (NULL);

	/* strip trailing /s */
	ptr = url + strlen(url) - 1;
	while (ptr > url && *ptr == '/')
		*ptr-- = '\0';
	if (*url == '\0') {
		xfree(pr);
		return (NULL); 
	}
	
	if ((ptr = strchr(url, ':')) != NULL) {
		*ptr++ = '\0';
		if (*ptr == '\0') {
			xfree(pr);
			return (NULL); 
		}
		pr->server.port = xstrdup(ptr);
	}

	pr->server.host = xstrdup(url);

	return (pr);
}

struct io *
connectio(struct server *srv, char *eol, char **cause)
{
	int		 fd = -1, error = 0, n;
	struct addrinfo	 hints;
	struct addrinfo	*ai;
	char		*fn = NULL;
	SSL_CTX		*ctx;
	SSL		*ssl;

	if (srv->ai == NULL) {
		memset(&hints, 0, sizeof hints);
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		error = getaddrinfo(srv->host, srv->port, &hints, &srv->ai);
		if (error != 0) {
			*cause = xstrdup(gai_strerror(error));
			return (NULL);
		}
	}

	for (ai = srv->ai; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			fn = "socket";
			continue;
		}
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			error = errno;
			close(fd);
			errno = error;
			fd = -1;
			fn = "connect";
			continue;
		}
		break;
	}

	if (fd < 0) {
		xasprintf(cause, "%s: %s", fn, strerror(errno));
		return (NULL);
	}
	if (!srv->ssl)
		return (io_create(fd, NULL, eol));

	ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);	
	
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		close(fd);
		xasprintf(cause, "SSL_new: %s", SSL_err());
		return (NULL);
	}

	if (SSL_set_fd(ssl, fd) != 1) {
		close(fd);
		xasprintf(cause, "SSL_set_fd: %s", SSL_err());
		return (NULL);
	}

	SSL_set_connect_state(ssl);
	if ((n = SSL_connect(ssl)) < 1) {
		close(fd);
		n = SSL_get_error(ssl, n);
		xasprintf(cause, "SSL_connect: %d: %s", n, SSL_err());
		return (NULL);
	}		

	return (io_create(fd, ssl, eol));
}
