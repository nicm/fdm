/* $Id$ */

/*
 * Copyright (c) 2005 Nicholas Marriott <nicm__@ntlworld.com>
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
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "fdm.h"

#undef	IO_DEBUG

int	io_push(struct io *);
int	io_fill(struct io *);

/* Create a struct io for the specified socket and SSL descriptors. */
struct io *
io_create(int fd, SSL *ssl, const char *eol, int timeout)
{
	struct io	*io;
	int		 mode;

	io = xcalloc(1, sizeof *io);
	io->fd = fd;
	io->ssl = ssl;
	io->dup_fd = -1;

	/* Set non-blocking. */
	if ((mode = fcntl(fd, F_GETFL)) == -1)
		fatal("fcntl");
	if (fcntl(fd, F_SETFL, mode | O_NONBLOCK) == -1)
		fatal("fcntl");

	io->flags = 0;
	io->error = NULL;

	io->rd = buffer_create(IO_BLOCKSIZE);
	io->wr = buffer_create(IO_BLOCKSIZE);

	io->lbuf = NULL;
	io->llen = 0;

	io->timeout = timeout;
	io->eol = eol;

	return (io);
}

/* Mark io as read only. */
void
io_readonly(struct io *io)
{
	buffer_destroy(io->wr);
	io->wr = NULL;
}

/* Mark io as write only. */
void
io_writeonly(struct io *io)
{
	buffer_destroy(io->rd);
	io->rd = NULL;
}

/* Free a struct io. */
void
io_free(struct io *io)
{
	if (io->lbuf != NULL)
		xfree(io->lbuf);
	if (io->error != NULL)
		xfree(io->error);
	if (io->rd != NULL)
		buffer_destroy(io->rd);
	if (io->wr != NULL)
		buffer_destroy(io->wr);
	xfree(io);
}

/* Close io sockets. */
void
io_close(struct io *io)
{
	if (io->ssl != NULL) {
		SSL_CTX_free(SSL_get_SSL_CTX(io->ssl));
		SSL_free(io->ssl);
	}
	close(io->fd);
}

/* Poll multiple IOs. */
int
io_polln(struct io **ios, u_int n, struct io **rio, int timeout, char **cause)
{
	struct io	*io;
	struct pollfd    pfds[IO_POLLFDS], *pfd;
	int		 error;
	u_int		 i;

	if (n > IO_POLLFDS)
		fatalx("io: too many fds");

	/* Check all the ios. */
	for (i = 0; i < n; i++) {
		io = *rio = ios[i];
		if (io == NULL)
			continue;
		if (io->error != NULL) {
			if (cause != NULL)
				*cause = xstrdup(io->error);
			return (-1);
		}
		if (IO_CLOSED(io))
			return (0);
	}

	/* Create the poll structure. */
	memset(pfds, 0, sizeof pfds);
	for (i = 0; i < n; i++) {
 		pfd = &pfds[i];

		io = *rio = ios[i];
		if (io == NULL) {
			pfd->fd = -1;
			continue;
		}

		if (io->ssl != NULL)
			pfd->fd = SSL_get_fd(io->ssl);
		else
			pfd->fd = io->fd;
		pfd->events = 0;
		if (io->rd != NULL)
			pfd->events |= POLLIN;
		if (io->wr != NULL && (BUFFER_USED(io->wr) != 0 ||
		    (io->flags & (IOF_NEEDFILL|IOF_NEEDPUSH|IOF_MUSTWR)) != 0))
			pfd->events |= POLLOUT;
	}

	/* Do the poll. */
	error = poll(pfds, n, timeout);
	if (error == 0 || error == -1) {
		if (error == 0 && timeout == 0) {
			errno = EAGAIN;
			return (-1);
		}
		if (error == 0)
			errno = ETIMEDOUT;
		*rio = NULL;
		if (errno == EINTR)
			return (1);
		if (cause != NULL)
			xasprintf(cause, "io: poll: %s", strerror(errno));
		return (-1);
	}

	/* And check all the ios. */
	for (i = 0; i < n; i++) {
		pfd = &pfds[i];

		io = *rio = ios[i];
		if (io == NULL)
			continue;

		/* Close on POLLERR or POLLNVAL hard. */
		if (pfd->revents & (POLLERR|POLLNVAL)) {
			io->flags |= IOF_CLOSED;
			continue;
		}
		/* Close on POLLHUP but only if there is nothing to read. */
		if (pfd->revents & POLLHUP && (pfd->revents & POLLIN) == 0) {
			io->flags |= IOF_CLOSED;
			continue;
		}

		if ((io->flags & (IOF_NEEDPUSH|IOF_NEEDFILL)) != 0) {
			/*
			 * If a repeated read/write is necessary, the socket
			 * must be ready for both reading and writing
			 */
			if (pfd->revents & (POLLOUT|POLLIN)) {
				if (io->flags & IOF_NEEDPUSH) {
					switch (io_push(io)) {
					case 0:
						io->flags |= IOF_CLOSED;
						continue;
					case -1:
						goto error;
					}
				}
				if (io->flags & IOF_NEEDFILL) {
					switch (io_fill(io)) {
					case 0:
						io->flags |= IOF_CLOSED;
						continue;
					case -1:
						goto error;
					}
				}
			}
			continue;
		}

		/* Otherwise try to read and write. */
		if (io->wr != NULL && pfd->revents & POLLOUT) {
			switch (io_push(io)) {
			case 0:
				io->flags |= IOF_CLOSED;
				continue;
			case -1:
				goto error;
			}
		}
		if (io->rd != NULL && pfd->revents & POLLIN) {
			switch (io_fill(io)) {
			case 0:
				io->flags |= IOF_CLOSED;
				continue;
			case -1:
				goto error;
			}
		}
	}

	return (1);

error:
	if (cause != NULL)
		*cause = xstrdup(io->error);

	return (-1);
}

/* Poll the io. */
int
io_poll(struct io *io, char **cause)
{
	struct io	*rio;
	int		 timeout;

	timeout = io->timeout;
	return (io_polln(&io, 1, &rio, timeout, cause));
}

/*
 * Fill read buffer. Returns 0 for closed, -1 for error, 1 for success,
 * a la read(2).
 */
int
io_fill(struct io *io)
{
	ssize_t	n;

#ifdef IO_DEBUG
 	log_debug3("io_fill: in");
#endif

	/* Ensure there is at least some minimum space in the buffer. */
	buffer_ensure(io->rd, IO_BLOCKSIZE);

	/* Attempt to read as much as the buffer has available. */
	if (io->ssl == NULL) {
		n = read(io->fd, BUFFER_IN(io->rd), BUFFER_FREE(io->rd));
		if (n == 0 || (n == -1 && errno == EPIPE))
			return (0);
		if (n == -1 && errno != EINTR && errno != EAGAIN) {
			if (io->error != NULL)
				xfree(io->error);
			xasprintf(&io->error, "io: read: %s", strerror(errno));
			return (-1);
		}
	} else {
		n = SSL_read(io->ssl, BUFFER_IN(io->rd), BUFFER_FREE(io->rd));
		if (n == 0)
			return (0);
		if (n < 0) {
			switch (n = SSL_get_error(io->ssl, n)) {
			case SSL_ERROR_WANT_READ:
				/*
				 * A repeat is certain (poll on the socket will
				 * still return data ready) so this can be
				 * ignored.
				 */
				break;
			case SSL_ERROR_WANT_WRITE:
				io->flags |= IOF_NEEDFILL;
				break;
			default:
				if (io->error != NULL)
					xfree(io->error);
				io->error = sslerror2(n, "SSL_read");
				return (-1);
			}
		}
	}

	/* Test for > 0 since SSL_read can return any -ve on error. */
	if (n > 0) {
#ifdef IO_DEBUG
		log_debug3("io_fill: read %zd bytes", n);
#endif

		/* Copy out the duplicate fd. Errors are just ignored. */
		if (io->dup_fd != -1) {
			write(io->dup_fd, "< ", 2);
			write(io->dup_fd, BUFFER_IN(io->rd), n);
		}

		/* Adjust the buffer size. */
		buffer_added(io->rd, n);

		/* Reset the need flags. */
		io->flags &= ~IOF_NEEDFILL;
	}

#ifdef IO_DEBUG
	log_debug3("io_fill: out");
#endif

	return (1);
}

/* Empty write buffer. */
int
io_push(struct io *io)
{
	ssize_t	n;

#ifdef IO_DEBUG
 	log_debug3("io_push: in");
#endif

	/* If nothing to write, return. */
	if (BUFFER_USED(io->wr) == 0)
		return (1);

	/* Write as much as possible. */
	if (io->ssl == NULL) {
		n = write(io->fd, BUFFER_OUT(io->wr), BUFFER_USED(io->wr));
		if (n == 0 || (n == -1 && errno == EPIPE))
			return (0);
		if (n == -1 && errno != EINTR && errno != EAGAIN) {
			if (io->error != NULL)
				xfree(io->error);
			xasprintf(&io->error, "io: write: %s", strerror(errno));
			return (-1);
		}
	} else {
		n = SSL_write(io->ssl, BUFFER_OUT(io->wr), BUFFER_USED(io->wr));
		if (n == 0)
			return (0);
		if (n < 0) {
			switch (n = SSL_get_error(io->ssl, n)) {
			case SSL_ERROR_WANT_READ:
				io->flags |= IOF_NEEDPUSH;
				break;
			case SSL_ERROR_WANT_WRITE:
				/*
				 * A repeat is certain (io->wsize is still !=
				 * 0) so this can be ignored
				 */
				break;
			default:
				if (io->error != NULL)
					xfree(io->error);
				io->error = sslerror2(n, "SSL_write");
				return (-1);
			}
		}
	}

	/* Test for > 0 since SSL_write can return any -ve on error. */
	if (n > 0) {
#ifdef IO_DEBUG
		log_debug3("io_push: wrote %zd bytes", n);
#endif

		/* Copy out the duplicate fd. */
		if (io->dup_fd != -1) {
			write(io->dup_fd, "> ", 2);
			write(io->dup_fd, BUFFER_OUT(io->wr), n);
		}

		/* Adjust the buffer size. */
		buffer_removed(io->wr, n);

		/* Reset the need flags. */
		io->flags &= ~IOF_NEEDPUSH;
	}

#ifdef IO_DEBUG
	log_debug3("io_push: out");
#endif

	return (1);
}

/* Return a specific number of bytes from the read buffer, if available. */
void *
io_read(struct io *io, size_t len)
{
	void	*buf;

	if (io->error != NULL)
		return (NULL);

	if (BUFFER_USED(io->rd) < len)
		return (NULL);

	buf = xmalloc(len);
	buffer_read(io->rd, buf, len);

	return (buf);
}

/* Return a specific number of bytes from the read buffer, if available. */
int
io_read2(struct io *io, void *buf, size_t len)
{
	if (io->error != NULL)
		return (-1);

	if (BUFFER_USED(io->rd) < len)
		return (-1);

	buffer_read(io->rd, buf, len);

	return (0);
}

/* Write a block to the io write buffer. */
void
io_write(struct io *io, const void *buf, size_t len)
{
	if (io->error != NULL)
		return;

	buffer_write(io->wr, buf, len);

#ifdef IO_DEBUG
	log_debug3("io_write: %zu bytes. wsize=%zu wspace=%zu", len, io->wsize,
	    io->wspace);
#endif
}

/*
 * Return a line from the read buffer. EOL is stripped and the string returned
 * is zero-terminated.
 */
char *
io_readline2(struct io *io, char **buf, size_t *len)
{
	char	*ptr, *base;
	size_t	 size, maxlen, eollen;

	if (io->error != NULL)
		return (NULL);

#ifdef IO_DEBUG
	log_debug3("io_readline2: in: off=%zu used=%zu", io->roff, io->rsize);
#endif

	maxlen = BUFFER_USED(io->rd);
	if (maxlen > IO_MAXLINELEN)
		maxlen = IO_MAXLINELEN;
	eollen = strlen(io->eol);
	if (BUFFER_USED(io->rd) < eollen)
		return (NULL);

	base = ptr = BUFFER_OUT(io->rd);
	for (;;) {
		/* Find the first character in the EOL string. */
		ptr = memchr(ptr, *io->eol, maxlen - (ptr - base));

		if (ptr != NULL) {
			/* Found. Is there enough space for the rest? */
			if (ptr - base + eollen > maxlen) {
				/*
				 * No, this isn't it. Set ptr to NULL to handle
				 * as not found.
				 */
				ptr = NULL;
			} else if (strncmp(ptr, io->eol, eollen) == 0) {
				/* This is an EOL. */
				size = ptr - base;
				break;
			}
		}
		if (ptr == NULL) {
			/*
			 * Not found within the length searched. If that was
			 * the maximum length, this is an error.
			 */
			if (maxlen == IO_MAXLINELEN) {
				if (io->error != NULL)
					xfree(io->error);
				io->error =
				    xstrdup("io: maximum line length exceeded");
				return (NULL);
			}
			/*
			 * If the socket has closed, just return all the data.
			 */
			if (!IO_CLOSED(io))
				return (NULL);
			size = BUFFER_USED(io->rd);

			ENSURE_FOR(*buf, *len, size, 1);
			buffer_read(io->rd, *buf, size);
			(*buf)[size] = '\0';
			return (*buf);
		}

		/* Start again from the next character. */
		ptr++;
	}

	/* Copy the line and remove it from the buffer. */
	ENSURE_FOR(*buf, *len, size, 1);
	buffer_read(io->rd, *buf, size);
	(*buf)[size] = '\0';

	/* Discard the EOL from the buffer. */
	buffer_removed(io->rd, eollen);

#ifdef IO_DEBUG
	log_debug3("io_readline2: out: off=%zu used=%zu", io->roff, io->rsize);
#endif

	return (*buf);
}

/* Return a line from the read buffer in a new buffer. */
char *
io_readline(struct io *io)
{
	char	*line;

	if (io->error != NULL)
		return (NULL);

	if (io->lbuf == NULL) {
		io->llen = IO_LINESIZE;
		io->lbuf = xmalloc(io->llen);
	}

	if ((line = io_readline2(io, &io->lbuf, &io->llen)) != NULL)
		io->lbuf = NULL;
	return (line);
}

/* Write a line to the io write buffer. */
void printflike2
io_writeline(struct io *io, const char *fmt, ...)
{
	va_list	 ap;

	if (io->error != NULL)
		return;

	va_start(ap, fmt);
	io_vwriteline(io, fmt, ap);
	va_end(ap);
}

/* Write a line to the io write buffer from a va_list. */
void
io_vwriteline(struct io *io, const char *fmt, va_list ap)
{
	int	 n;
	va_list	 aq;

	if (io->error != NULL)
		return;

	if (fmt != NULL) {
		va_copy(aq, ap);
		n = xvsnprintf(NULL, 0, fmt, aq);
		va_end(aq);

		buffer_ensure(io->wr, n + 1);
 		xvsnprintf(BUFFER_IN(io->wr), n + 1, fmt, ap);
		buffer_added(io->wr, n);
	}
	io_write(io, io->eol, strlen(io->eol));
}

/* Poll until a line is received. */
int
io_pollline(struct io *io, char **line, char **cause)
{
	int	res;

	if (io->lbuf == NULL) {
		io->llen = IO_LINESIZE;
		io->lbuf = xmalloc(io->llen);
	}

	if ((res = io_pollline2(io, line, &io->lbuf, &io->llen, cause)) == 1)
		io->lbuf = NULL;
	return (res);
}

/* Poll until a line is received, using a user buffer. */
int
io_pollline2(struct io *io, char **line, char **buf, size_t *len, char **cause)
{
	int	res;

	for (;;) {
		*line = io_readline2(io, buf, len);
		if (*line != NULL)
			return (1);

		if ((res = io_poll(io, cause)) != 1)
			return (res);
	}
}

/* Poll until all data in the write buffer has been written to the socket. */
int
io_flush(struct io *io, char **cause)
{
	while (BUFFER_USED(io->wr) != 0) {
		if (io_poll(io, cause) != 1)
			return (-1);
	}

	return (0);
}

/* Poll until len bytes have been read into the read buffer. */
int
io_wait(struct io *io, size_t len, char **cause)
{
	while (BUFFER_USED(io->rd) < len) {
		if (io_poll(io, cause) != 1)
			return (-1);
	}

	return (0);
}

/* Poll if there is lots of data to write. */
int
io_update(struct io *io, char **cause)
{
	if (BUFFER_USED(io->wr) < IO_FLUSHSIZE)
		return (1);

	return (io_poll(io, cause));
}
