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

	/* set non-blocking */
	if ((mode = fcntl(fd, F_GETFL)) == -1)
		fatal("fcntl");
	if (fcntl(fd, F_SETFL, mode | O_NONBLOCK) == -1)
		fatal("fcntl");

	io->flags = IO_RD|IO_WR;
	io->closed = 0;
	io->error = NULL;

	io->rspace = IO_BLOCKSIZE;
	io->rbase = xmalloc(io->rspace);
	io->rsize = 0;
	io->roff = 0;

	io->wspace = IO_BLOCKSIZE;
	io->wbase = xmalloc(io->wspace);
	io->wsize = 0;
	io->woff = 0;

	io->lbuf = NULL;
	io->llen = 0;

	io->timeout = timeout;
	io->eol = eol;

	return (io);
}

/* Free a struct io. */
void
io_free(struct io *io)
{
	if (io->lbuf != NULL)
		xfree(io->lbuf);
	if (io->error != NULL)
		xfree(io->error);
	xfree(io->rbase);
	if ((io->flags & IO_FIXED) == 0)
		xfree(io->wbase);
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

/* Poll if there is lots of data to write. */
int
io_update(struct io *io, char **cause)
{
	if (io->wsize < IO_FLUSHSIZE)
		return (1);

	return (io_poll(io, cause));
}

/* Poll multiple IOs. */
int
io_polln(struct io **ios, u_int n, struct io **rio, int timeout, char **cause)
{
	struct io	*io;
	struct pollfd    pfds[IO_POLLFDS], *pfd;
	int		 error;
	u_int		 i, j;

	if (n > IO_POLLFDS)
		fatalx("io: too many fds");

	/* check all the ios */
	for (i = 0; i < n; i++) {
		io = *rio = ios[i];
		if (io == NULL)
			continue;
		if (io->error != NULL) {
			if (cause != NULL)
				*cause = xstrdup(io->error);
			return (-1);
		}
		if (io->closed)
			return (0);
	}

	/* create the poll structure */
	memset(pfds, 0, sizeof pfds);
	j = 0;
	for (i = 0; i < n; i++) {
		io = *rio = ios[i];
		if (io == NULL)
			continue;
		pfd = &pfds[j];
		j++;
		if (io->ssl != NULL)
			pfd->fd = SSL_get_fd(io->ssl);
		else
			pfd->fd = io->fd;
		pfd->events = 0;
		if (io->flags & IO_RD)
			pfd->events |= POLLIN;
		if (io->flags & IO_WR && (io->wsize > 0 ||
		    (io->flags & (IO_NEEDFILL|IO_NEEDPUSH)) != 0))
			pfd->events |= POLLOUT;
	}

	/* do the poll */
	error = poll(pfds, j, timeout);
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

	/* and check all the ios */
	j = 0;
	for (i = 0; i < n; i++) {
		io = *rio = ios[i];
		if (io == NULL)
			continue;
		pfd = &pfds[j];
		j++;

		/* close on POLLERR or POLLNVAL hard */
		if (pfd->revents & (POLLERR|POLLNVAL)) {
			io->closed = 1;
			continue;
		}
		/* close on POLLHUP but only if there is nothing to read */ 
		if (pfd->revents & POLLHUP && (pfd->revents & POLLIN) == 0) {
			io->closed = 1;
			continue;
		}

		if ((io->flags & (IO_NEEDFILL|IO_NEEDPUSH)) != 0) {
			/* if a repeated read/write is necessary, the socket
			   must be ready for both reading and writing */
			if (pfd->revents & POLLOUT && pfd->revents & POLLIN) {
				if (io->flags & IO_NEEDFILL) {
					if ((error = io_fill(io)) != 1)
						goto error;
				}
				if (io->flags & IO_NEEDPUSH) {
					switch (io_push(io)) {
					case 0:
						io->closed = 1;
						continue;
					case -1:
						goto error;
					}
				}
			}
			continue;
		}

		/* otherwise try to read and write */
		if (pfd->revents & POLLOUT) {
			switch (io_push(io)) {
			case 0:
				io->closed = 1;
				continue;
			case -1:
				goto error;
			}
		}
		if (pfd->revents & POLLIN) {
			switch (io_fill(io)) {
			case 0:
				io->closed = 1;
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
	if (io->flags & IO_NOWAIT)
		timeout = 0;
	return (io_polln(&io, 1, &rio, timeout, cause));
}

/* Fill read buffer. Returns 0 for closed, -1 for error, 1 for success,
   a la read(2). */
int
io_fill(struct io *io)
{
	ssize_t	n;

#ifdef IO_DEBUG
 	log_debug3("io_fill: in");
#endif

	/* move data back to the base of the buffer */
	if (io->roff > 0) {
		memmove(io->rbase, io->rbase + io->roff, io->rsize);
		io->roff = 0;
	}

	/* ensure there is enough space */
	if (io->rspace - io->rsize < IO_BLOCKSIZE) {
		io->rspace += IO_BLOCKSIZE;
		if (io->rspace > IO_MAXBUFFERLEN) {
			if (io->error != NULL)
				xfree(io->error);
			io->error = xstrdup("io: maximum buffer length "
			    "exceeded");
			return (-1);
		}
		io->rbase = xrealloc(io->rbase, 1, io->rspace);
	}

	/* attempt to read a block */
	if (io->ssl == NULL) {
		n = read(io->fd, io->rbase + io->roff + io->rsize,
		    IO_BLOCKSIZE);
		if (n == 0 || (n == -1 && errno == EPIPE))
			return (0);
		if (n == -1 && errno != EINTR && errno != EAGAIN) {
			if (io->error != NULL)
				xfree(io->error);
			xasprintf(&io->error, "io: read: %s", strerror(errno));
			return (-1);
		}
	} else {
		n = SSL_read(io->ssl, io->rbase + io->roff + io->rsize,
		    IO_BLOCKSIZE);
		if (n == 0)
			return (0);
		if (n < 0) {
			switch (SSL_get_error(io->ssl, n)) {
			case SSL_ERROR_WANT_READ:
				/* a repeat is certain (poll on the socket
				   will still return data ready) so this can
				   be ignored */
				break;
			case SSL_ERROR_WANT_WRITE:
				io->flags |= IO_NEEDFILL;
				break;
			default:
				if (io->error != NULL)
					xfree(io->error);
				xasprintf(&io->error, "io: SSL_read: %s",
				    SSL_err());
				return (-1);
			}
		}
	}

	if (n != -1) {
#ifdef IO_DEBUG
		log_debug3("io_fill: read %zd bytes", n);
#endif

		/* copy out the duplicate fd. errors are irrelevent for this */
		if (io->dup_fd != -1) {
			write(io->dup_fd, "< ", 2);
			write(io->dup_fd, io->rbase + io->rsize, n);
		}

		/* increase the fill marker */
		io->rsize += n;

		/* reset the need flags */
		io->flags &= ~IO_NEEDFILL;
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

	/* if nothing to write, return */
	if (io->wsize == 0)
		return (1);

	/* write as much as possible */
	if (io->ssl == NULL) {
		n = write(io->fd, io->wbase + io->woff, io->wsize);
		if (n == 0 || (n == -1 && errno == EPIPE))
			return (0);
		if (n == -1 && errno != EINTR && errno != EAGAIN) {
			if (io->error != NULL)
				xfree(io->error);
			xasprintf(&io->error, "io: write: %s", strerror(errno));
			return (-1);
		}
	} else {
		n = SSL_write(io->ssl, io->wbase + io->woff, io->wsize);
		if (n == 0)
			return (0);
		if (n < 0) {
			switch (SSL_get_error(io->ssl, n)) {
			case SSL_ERROR_WANT_READ:
				io->flags |= IO_NEEDPUSH;
				break;
			case SSL_ERROR_WANT_WRITE:
				/* a repeat is certain (io->wsize is still != 0)
				   so this can be ignored */
				break;
			default:
				if (io->error != NULL)
					xfree(io->error);
				xasprintf(&io->error, "io: SSL_write: %s",
				    SSL_err());
				return (-1);
			}
		}
	}

	if (n != -1) {
#ifdef IO_DEBUG
		log_debug3("io_push: wrote %zd bytes", n);
#endif

		/* copy out the duplicate fd */
		if (io->dup_fd != -1) {
			write(io->dup_fd, "> ", 2);
			write(io->dup_fd, io->wbase + io->woff, n);
		}

		io->woff += n;
		io->wsize -= n;
		if ((io->flags & IO_FIXED) == 0 && io->woff > IO_BLOCKSIZE) {
			/* move the unwritten data down */
			memmove(io->wbase, io->wbase + io->woff, io->wsize);
			io->woff = 0;
		}

		/* reset the need flags */
		io->flags &= ~IO_NEEDPUSH;
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

	if ((io->flags & IO_RD) == 0)
		fatalx("io: read when flag unset");

	if (io->error != NULL)
		return (NULL);

	if (io->rsize < len)
		return (NULL);

	buf = xmalloc(len);
	memcpy(buf, io->rbase + io->roff, len);

	io->rsize -= len;
	io->roff += len;

	return (buf);
}

/* Return a specific number of bytes from the read buffer, if available. */
int
io_read2(struct io *io, void *buf, size_t len)
{
	if ((io->flags & IO_RD) == 0)
		fatalx("io: read when flag unset");

	if (io->error != NULL)
		return (1);

	if (io->rsize < len)
		return (1);

	memcpy(buf, io->rbase + io->roff, len);

	io->rsize -= len;
	io->roff += len;

	return (0);
}

/* Replace the write buffer with the specified one. */
void
io_writefixed(struct io *io, void *buf, size_t len)
{
	if ((io->flags & IO_WR) == 0)
		fatalx("io: write when flag unset");

	xfree(io->wbase);
	io->wbase = buf;
	io->wspace = 0;
	io->wsize = len;
	io->woff = 0;
	io->flags |= IO_FIXED;
}

/* Write a block to the io write buffer. */
void
io_write(struct io *io, const void *buf, size_t len)
{
	if ((io->flags & IO_WR) == 0)
		fatalx("io: write when flag unset");

	if (io->error != NULL)
		return;

	if (io->flags & IO_FIXED)
		fatalx("io: attempt to write to fixed buffer");

	if (len != 0) {
		ENSURE_FOR(io->wbase, io->wspace, io->wsize + io->woff, len);

		memcpy(io->wbase + io->woff + io->wsize, buf, len);
		io->wsize += len;
	}

#ifdef IO_DEBUG
	log_debug3("io_write: %zu bytes. wsize=%zu wspace=%zu", len, io->wsize,
	    io->wspace);
#endif
}

/* Return a line from the read buffer. EOL is stripped and the string
   returned is zero-terminated. */
char *
io_readline2(struct io *io, char **buf, size_t *len)
{
	char	*ptr;
	size_t	 off, maxlen, eollen;

	if ((io->flags & IO_RD) == 0)
		fatalx("io: read when flag unset");

	if (io->error != NULL)
		return (NULL);

#ifdef IO_DEBUG
	log_debug3("io_readline2: in: off=%zu used=%zu", io->roff, io->rsize);
#endif

	maxlen = io->rsize > IO_MAXLINELEN ? IO_MAXLINELEN : io->rsize;
	eollen = strlen(io->eol);

	if (io->rsize < eollen)
		return (NULL);

	ptr = io->rbase + io->roff;
	for (;;) {
		/* find the first EOL character */
		ptr = memchr(ptr, *io->eol, io->rsize - (ptr - io->rbase -
		    io->roff));

		if (ptr != NULL) {
			off = (ptr - io->rbase) - io->roff;

			if (off + eollen > maxlen) {
				/* if there isn't enough space for the rest of
				   the EOL, this isn't it */
				ptr = NULL;
			} else if (strncmp(ptr, io->eol, eollen) == 0) {
				/* the strings match, so this is it */
				break;
			}
		}
		if (ptr == NULL) {
			/* not found within the length searched. if that was
			   the maximum, it is an error */
			if (io->rsize > IO_MAXLINELEN) {
				if (io->error != NULL)
					xfree(io->error);
				io->error = xstrdup("io: maximum line length "
				    "exceeded");
				return (NULL);
			}
			/* if the socket has closed, just return the rest */
			if (io->closed) {
				ENSURE_FOR(*buf, *len, io->rsize, 1);
				memcpy(*buf, io->rbase + io->roff, io->rsize);
				(*buf)[io->rsize] = '\0';
				io->roff += io->rsize;
				io->rsize = 0;
				return (*buf);
			}
			return (NULL);
		}

		ptr++;
	}

	/* copy the line */
	ENSURE_FOR(*buf, *len, off, 1);
	memcpy(*buf, io->rbase + io->roff, off);
	(*buf)[off] = '\0';

	/* adjust the buffer positions */
	io->roff += off + eollen;
	io->rsize -= off + eollen;

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

	if ((io->flags & IO_WR) == 0)
		fatalx("io: write when flag unset");

	if (io->error != NULL)
		return;

	if (io->flags & IO_FIXED)
		fatalx("io: attempt to write to fixed buffer");

	if (fmt != NULL) {
		va_copy(aq, ap);
		n = xvsnprintf(NULL, 0, fmt, aq);
		va_end(aq);

		ENSURE_FOR(io->wbase, io->wspace, io->wsize + io->woff, n + 1);
		
 		xvsnprintf(io->wbase + io->woff + io->wsize, n + 1, fmt, ap);
		io->wsize += n;
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
	int	flags;

	flags = io->flags;
	io->flags &= ~IO_NOWAIT;

	while (io->wsize > 0) {
		if (io_poll(io, cause) != 1) {
			io->flags = flags;
			return (-1);
		}
	}

	io->flags = flags;
	return (0);
}

/* Poll until len bytes have been read into the read buffer. */
int
io_wait(struct io *io, size_t len, char **cause)
{
	int	flags;

	flags = io->flags;
	io->flags &= ~IO_NOWAIT;

	while (io->rsize < len) {
		if (io_poll(io, cause) != 1) {
			io->flags = flags;
			return (-1);
		}
	}
	
	io->flags = flags;
	return (0);
}
