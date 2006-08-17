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

#ifndef INFTIM	/* stupid Linux */
#define INFTIM -1
#endif

#include "fdm.h"

int	io_push(struct io *);
int	io_fill(struct io *);

/* Create a struct io for the specified socket and SSL descriptors. */
struct io *
io_create(int fd, SSL *ssl, const char *eol)
{
	struct io	*io;
	int		 mode;

	io = xcalloc(1, sizeof *io);
	io->fd = fd;
	io->ssl = ssl;
	if (io->ssl != NULL)
		io->need_wr = 1; /* initial write in case SSL needs it */
	io->dup_fd = -1;

	/* set non-blocking */
	if ((mode = fcntl(fd, F_GETFL)) == -1)
		fatal("fcntl");
	if (fcntl(fd, F_SETFL, mode | O_NONBLOCK) == -1)
		fatal("fcntl");

	io->need_wr = 0;
	io->closed = 0;

	io->rspace = IO_BLOCKSIZE;
	io->rbase = xmalloc(io->rspace);
	io->rsize = 0;
	io->roff = 0;

	io->wspace = IO_BLOCKSIZE;
	io->wbase = xmalloc(io->wspace);
	io->wsize = 0;

	io->eol = eol;

	return (io);
}

/* Free a struct io. */
void
io_free(struct io *io)
{
	xfree(io->rbase);
	xfree(io->wbase);
	xfree(io);
}

/* Poll if there is lots of data to write. */
int
io_update(struct io *io)
{
	if (io->wsize < IO_FLUSHSIZE)
		return (1);

	return (io_poll(io));
}

/* Poll the io. */
int
io_poll(struct io *io)
{
	struct pollfd	pfd;
	int		error;

	if (io->closed)
		return (0);

	if (io->ssl != NULL)
		pfd.fd = SSL_get_fd(io->ssl);
	else
		pfd.fd = io->fd;
	pfd.events = POLLIN;
	if (io->wsize > 0 || io->need_wr)
		pfd.events |= POLLOUT;

	log_debug3("io_poll: in: roff=%zu rsize=%zu rspace=%zu "
	    "wsize=%zu wspace=%zu", io->roff, io->rsize, io->rspace, 
	    io->wsize, io->wspace);

	error = poll(&pfd, 1, INFTIM);
	if (error == -1 && errno != EINTR)
		fatal("poll");
	if (error == 0 || error == -1)
		return (-1);
	
	if (pfd.revents & POLLERR || pfd.revents & POLLNVAL)
		goto error;
	if (pfd.revents & POLLIN) {
		if ((error = io_fill(io)) != 1) {
			if (error == -1)
				return (-1);
			goto error;
		}
	}
	if (pfd.revents & POLLOUT) {
		if ((error = io_push(io)) != 1) {
			if (error == -1)
				return (-1);
			goto error;
		}
	}

	log_debug3("io_poll: out: roff=%zu rsize=%zu rspace=%zu "
	    "wsize=%zu wspace=%zu", io->roff, io->rsize, io->rspace, 
	    io->wsize, io->wspace);

	return (1);

error:
	io->closed = 1;
	return (1);
}

/* Fill read buffer. Returns 0 for closed, -1 for error, 1 for success,
   a la read(2). */
int
io_fill(struct io *io)
{
	ssize_t	n;

 	log_debug3("io_fill: in");

	/* move data back to the base of the buffer */
	if (io->roff > 0) {
		memmove(io->rbase, io->rbase + io->roff, io->rsize);
		io->roff = 0;
	}

	/* ensure there is enough space */
	if (io->rspace - io->rsize < IO_BLOCKSIZE) {
		io->rspace += IO_BLOCKSIZE;
		if (io->rspace > IO_MAXBUFFERLEN) {
			log_warnx("io: maximum buffer length exceeded");
			return (-1);
		}
		io->rbase = xrealloc(io->rbase, 1, io->rspace);
	}

	/* attempt to read a block */
	if (io->ssl == NULL) {
		n = read(io->fd, io->rbase + io->roff + io->rsize,
		    IO_BLOCKSIZE);
		if (n == 0)
			return (0);
		if (n == -1 && errno != EINTR && errno != EAGAIN) {
			log_warn("read");
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
				break;
			case SSL_ERROR_WANT_WRITE:
				io->need_wr = 1;
				break;
			default:
				log_warnx("SSL_read: %s", SSL_err());
				return (-1);
			}
		}
	}

	if (n != -1) {
		log_debug3("io_fill: read %zd bytes", n);

		/* copy out the duplicate fd. errors are irrelevent for this */
		if (io->dup_fd != -1 && !conf.syslog) {
			write(io->dup_fd, "< ", 3);
			write(io->dup_fd, io->rbase + io->rsize, n);
		}

		/* increase the fill marker */
		io->rsize += n;
	}		

	log_debug3("io_fill: out");

	return (1);
}

/* Empty write buffer. */
int
io_push(struct io *io) 
{
	ssize_t	n;

 	log_debug3("io_push: in");

	/* if nothing to write, return */
	if (io->wsize == 0)
		return (1);

	/* write as much as possible */
	if (io->ssl == NULL) {
		n = write(io->fd, io->wbase, io->wsize);
		if (n == 0)
			return (0);
		if (n == -1 && errno != EINTR && errno != EAGAIN) {
			log_warn("write");
			return (-1);
		}
	} else {
		n = SSL_write(io->ssl, io->wbase, io->wsize);
		if (n == 0)
			return (0);
		if (n < 0) {
			switch (SSL_get_error(io->ssl, n)) {
			case SSL_ERROR_WANT_READ:
				break;
			case SSL_ERROR_WANT_WRITE:
				io->need_wr = 1;
				break;
			default:
				log_warnx("SSL_write: %s", SSL_err());
				return (-1);
			}
		}
	}

	if (n != -1) {
		log_debug3("io_push: wrote %zd bytes", n);

		/* copy out the duplicate fd */
		if (io->dup_fd != -1 && !conf.syslog) {
			write(io->dup_fd, "> ", 3);
			write(io->dup_fd, io->wbase, n);
		}

		/* move the unwritten data down and adjust the next pointer */
		memmove(io->wbase, io->wbase + n, io->wsize - n);
		io->wsize -= n;

		/* reset the need-write flag */
		io->need_wr = 0;
	}

	log_debug3("io_push: out");

	return (1);
}

/* Return a specific number of bytes from the read buffer, if available. */
void *
io_read(struct io *io, size_t len)
{
	void	*buf;

	if (io->rsize < len)
		return (NULL);

	buf = xmalloc(len);
	memcpy(buf, io->rbase + io->roff, len);

	io->rsize -= len;
	io->roff += len;

	return (buf);
}

/* Write a block to the io write buffer. */
void
io_write(struct io *io, const void *buf, size_t len)
{
	if (len != 0) {
		ENSURE_SIZE(io->wbase, io->wspace, io->wsize + len);
		
		memcpy(io->wbase + io->wsize, buf, len);
		io->wsize += len;
	}

	log_debug3("io_write: %zu bytes. wsize=%zu wspace=%zu", io->wsize,
	    io->wspace);
}

/* Return a line from the read buffer. EOL is stripped and the string
   returned is zero-terminated. */
char *
io_readline(struct io *io)
{
	char	*ptr, *line;
	size_t	 off, maxlen, eollen;

	if (io->rsize <= 1)
		return (NULL);

	log_debug3("io_readline: in: off=%zu used=%zu", io->roff, io->rsize);

	maxlen = io->rsize > IO_MAXLINELEN ? IO_MAXLINELEN : io->rsize;
	eollen = strlen(io->eol);

	ptr = io->rbase + io->roff;
	for (;;) {
		/* find the first EOL character */
		ptr = memchr(ptr, *io->eol, maxlen);

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
				log_warnx("io: maximum line length exceeded");
				io->closed = 1;
				return (NULL);
			}
			/* if the socket has closed, just return the rest */
			if (io->closed) {
				line = xmalloc(io->rsize + 1);
				memcpy(line, io->rbase + io->roff, io->rsize);
				line[io->rsize] = '\0';
				io->roff += io->rsize;
				io->rsize = 0;
			}
			return (NULL);
		}

		ptr++;
	}

	/* copy the line */
	line = xmalloc(off + 1);
	memcpy(line, io->rbase + io->roff, off);
	line[off] = '\0';

	/* adjust the buffer positions */
	io->roff += off + eollen;
	io->rsize -= off + eollen;

	log_debug3("io_readline: out: off=%zu used=%zu", io->roff, io->rsize);

	return (line);
}

/* Write a line to the io write buffer. */
void
io_writeline(struct io *io, const char *fmt, ...)
{
	va_list	 ap;

	log_debug3("io_writeline: fmt=%s", fmt);

	va_start(ap, fmt);
	io_vwriteline(io, fmt, ap);
	va_end(ap);
}

/* Write a line to the io write buffer from a va_list. */
void
io_vwriteline(struct io *io, const char *fmt, va_list ap)
{
	char 	*buf;
	int	 len;

	if ((len = vasprintf(&buf, fmt, ap)) == -1)
		fatal("vasprintf");

	io_write(io, buf, len);
	io_write(io, io->eol, strlen(io->eol));

	xfree(buf);
}

/* Poll until all data in the write buffer has been written to the socket. */
int
io_flush(struct io *io)
{
	while (io->wsize > 0) {
		if (io_poll(io) != 1)
			return (-1);
	}
	
	return (0);
}

/* Poll until len bytes have been read into the read buffer. */
int
io_wait(struct io *io, size_t len)
{
	while (io->rsize < len) {
		if (io_poll(io) != 1)
			return (-1);
	}

	return (0);
}
