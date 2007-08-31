/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm__@ntlworld.com>
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

#ifndef IO_H
#define IO_H

/* Buffer macros. */
#define BUFFER_USED(b) ((b)->size)
#define BUFFER_FREE(b) ((b)->space - (b)->off - (b)->size)
#define BUFFER_IN(b) ((b)->base + (b)->off + (b)->size)
#define BUFFER_OUT(b) ((b)->base + (b)->off)

/* Buffer structure. */
struct buffer {
	u_char		*base;		/* buffer start */
	size_t		 space;		/* total size of buffer */

	size_t		 size;		/* size of data in buffer */
	size_t		 off;		/* offset of data in buffer */
};

/* Limits at which to fail. */
#define IO_MAXLINELEN (1024 * 1024) 		/* 1 MB */

/* IO line endings. */
#define IO_CRLF "\r\n"
#define IO_CR   "\r"
#define IO_LF   "\n"

/* Initial block size of buffer and minimum amount to try to read. */
#define IO_BLOCKSIZE 16384
#define IO_WATERMARK 12288

/* Initial line buffer length. */
#define IO_LINESIZE 256

/* Amount to poll after in io_update. */
#define IO_FLUSHSIZE (2 * IO_BLOCKSIZE)

/* IO macros. */
#define IO_ROUND(n) (((n / IO_BLOCKSIZE) + 1) * IO_BLOCKSIZE)
#define IO_CLOSED(io) ((io)->flags & IOF_CLOSED)
#define IO_ERROR(io) ((io)->error)
#define IO_RDSIZE(io) (BUFFER_USED((io)->rd))
#define IO_WRSIZE(io) (BUFFER_USED((io)->wr))

/* IO structure. */
struct io {
	int		 fd;
	int		 dup_fd;	/* duplicate all data to this fd */
	SSL		*ssl;

	char		*error;

	int		 flags;
#define IOF_NEEDFILL 0x1
#define IOF_NEEDPUSH 0x2
#define IOF_CLOSED 0x4
#define IOF_MUSTWR 0x8

	struct buffer	*rd;
	struct buffer	*wr;

	char		*lbuf;		/* line buffer */
	size_t		 llen;		/* line buffer size */

	const char	*eol;
};

/* List of ios. */
ARRAY_DECL(iolist, struct io *);

/* buffer.c */
struct buffer 	*buffer_create(size_t);
void		 buffer_destroy(struct buffer *);
void		 buffer_clear(struct buffer *);
void		 buffer_ensure(struct buffer *, size_t);
void		 buffer_add(struct buffer *, size_t);
void		 buffer_reverse_add(struct buffer *, size_t);
void		 buffer_remove(struct buffer *, size_t);
void		 buffer_reverse_remove(struct buffer *, size_t);
void		 buffer_insert_range(struct buffer *, size_t, size_t);
void		 buffer_delete_range(struct buffer *, size_t, size_t);
void		 buffer_write(struct buffer *, const void *, size_t);
void		 buffer_read(struct buffer *, void *, size_t);

/* io.c */
struct io	*io_create(int, SSL *, const char *);
void		 io_readonly(struct io *);
void		 io_writeonly(struct io *);
void		 io_free(struct io *);
void		 io_close(struct io *);
int		 io_polln(struct io **, u_int, struct io **, int, char **);
int		 io_poll(struct io *, int, char **);
int		 io_read2(struct io *, void *, size_t);
void 		*io_read(struct io *, size_t);
void		 io_write(struct io *, const void *, size_t);
char 		*io_readline2(struct io *, char **, size_t *);
char 		*io_readline(struct io *);
void printflike2 io_writeline(struct io *, const char *, ...);
void		 io_vwriteline(struct io *, const char *, va_list);
int		 io_pollline2(struct io *, char **, char **, size_t *, int,
		     char **);
int		 io_pollline(struct io *, char **, int, char **);
int		 io_flush(struct io *, int, char **);
int		 io_wait(struct io *, size_t, int, char **);
int		 io_update(struct io *, int, char **);

#endif /* IO_H */
