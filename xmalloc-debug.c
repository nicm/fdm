/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm@users.sourceforge.net>
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

#ifdef DEBUG

#include <sys/types.h>

#include <string.h>

#include "fdm.h"

#define XMALLOC_SLOTS 8192

struct xmalloc_blk {
	const char		*file;
	u_int		 	 line;

	void			*ptr;
	size_t	 	 	 size;
};

enum xmalloc_type {
	XMALLOC_NONE = 0,
	XMALLOC_FREE,
	XMALLOC_REALLOC,
	XMALLOC_MALLOC
};

struct xmalloc_call {
	const char		*file;
	u_int			 line;

	enum xmalloc_type	 type;
	u_int			 count;
};

struct {
	size_t		 	 allocated;
	size_t		 	 freed;
	size_t		 	 peak;
	u_int		 	 frees;
	u_int		 	 mallocs;
	u_int		 	 reallocs;

	struct xmalloc_blk	 list[XMALLOC_SLOTS];
	struct xmalloc_call	 calls[XMALLOC_SLOTS];
} xmalloc_ctx;

#define XMALLOC_PRINT log_debug2

#define XMALLOC_PEEK 8
#define XMALLOC_LINES 32

#define XMALLOC_UPDATE(xctx) do {					\
	if ((xctx)->allocated - (xctx)->freed > (xctx)->peak)		\
		(xctx)->peak = (xctx)->allocated - (xctx)->freed;	\
} while (0)

void			 xmalloc_called(const char *, u_int, enum xmalloc_type);
struct xmalloc_blk	*xmalloc_find(void *);
void			 xmalloc_new(const char *, u_int, void *, size_t);
void			 xmalloc_change(const char *,u_int, void *, void *,
			     size_t);
void			 xmalloc_free(const char *, u_int, void *);

void
xmalloc_called(const char *file, u_int line, enum xmalloc_type type)
{
	u_int			 i;

	for (i = 0; i < XMALLOC_SLOTS; i++) {
		if (xmalloc_ctx.calls[i].type  == type && 
		    xmalloc_ctx.calls[i].line == line &&
		    strcmp(xmalloc_ctx.calls[i].file, file) == 0)
			break;
	}
	if (i == XMALLOC_SLOTS) {
		for (i = 0; i < XMALLOC_SLOTS; i++) {
			if (xmalloc_ctx.calls[i].type == XMALLOC_NONE)
				break;
		}
		if (i == XMALLOC_SLOTS)
			fatalx("xmalloc_called: no space");
	}

	xmalloc_ctx.calls[i].type = type;
	xmalloc_ctx.calls[i].line = line;
	xmalloc_ctx.calls[i].file = file;
	xmalloc_ctx.calls[i].count++;
}

void
xmalloc_callreport(const char *hdr)
{
	struct xmalloc_call	*call;
	u_int			 i;
	const char		*type = "";
	char			 fn[64];

	for (i = 0; i < XMALLOC_SLOTS; i++) {
		call = &xmalloc_ctx.calls[i];

		switch (call->type) {
		case XMALLOC_NONE:
			continue;
		case XMALLOC_MALLOC:
			type = "malloc";
			break;
		case XMALLOC_FREE:
			type = "free";
			break;
		case XMALLOC_REALLOC:
			type = "realloc";
			break;
		}

		xsnprintf(fn, sizeof fn, "%s:%u", call->file, call->line);
		XMALLOC_PRINT("%s: %-10s %-24s %u", hdr, type, fn, call->count);
	}
}


struct xmalloc_blk *
xmalloc_find(void *ptr)
{
	u_int	i;

	for (i = 0; i < XMALLOC_SLOTS; i++) {
		if (xmalloc_ctx.list[i].ptr == ptr)
			return (&xmalloc_ctx.list[i]);
	}

	return (NULL);
}

void
xmalloc_clear(void)
{
	xmalloc_ctx.allocated = 0;
	xmalloc_ctx.freed = 0;
	xmalloc_ctx.peak = 0;
	xmalloc_ctx.frees = 0;
	xmalloc_ctx.mallocs = 0;
	xmalloc_ctx.reallocs = 0;

	memset(xmalloc_ctx.list, 0, sizeof xmalloc_ctx.list);
	memset(xmalloc_ctx.calls, 0, sizeof xmalloc_ctx.calls);
}

void
xmalloc_report(const char *hdr)
{
 	struct xmalloc_blk	*blk;
 	char	 		 line[256];
 	int			 len;
 	size_t	 		 off, size;
  	u_int	 		 i, j, n;

 	XMALLOC_PRINT("%s: allocated=%zu, freed=%zu, difference=%zd, peak=%zu",
 	    hdr, xmalloc_ctx.allocated, xmalloc_ctx.freed,
	    xmalloc_ctx.allocated - xmalloc_ctx.freed, xmalloc_ctx.peak);
 	XMALLOC_PRINT("%s: mallocs=%u, reallocs=%u, frees=%u", hdr,
	    xmalloc_ctx.mallocs, xmalloc_ctx.reallocs, xmalloc_ctx.frees);

	xmalloc_callreport(hdr);

 	if (xmalloc_ctx.allocated == xmalloc_ctx.freed)
 		return;

	n = 0;
	off = 0;
	for (i = 0; i < XMALLOC_SLOTS; i++) {
		blk = &xmalloc_ctx.list[i];
		if (blk->ptr == NULL)
			continue;

		n++;
		if (n >= XMALLOC_LINES)
			continue;

		len = xsnprintf(line, sizeof line, "%u %s:%u [%p %zu:", n - 1,
		    blk->file, blk->line, blk->ptr, blk->size);
		if ((size_t) len >= sizeof line)
			continue;
		off = len;

		size = blk->size < XMALLOC_PEEK ? blk->size : XMALLOC_PEEK;
		for (j = 0; j < size; j++) {
			if (off >= (sizeof line) - 3)
				break;

			if (((u_char *) blk->ptr)[j] > 31) {
				line[off++] = ((u_char *) blk->ptr)[j];
				continue;
			}

			len = xsnprintf(line + off, (sizeof line) - off,
			    "\\%03hho", ((u_char *) blk->ptr)[j]);
			if ((size_t) len >= (sizeof line) - off)
				break;
			off += len;
		}
		line[off++] = ']';
		line[off] = '\0';

		XMALLOC_PRINT("%s: %s", hdr, line);
	}

	XMALLOC_PRINT("%s: %u unfreed blocks", hdr, n);
}

void
xmalloc_new(const char *file, u_int line, void *ptr, size_t size)
{
	struct xmalloc_blk	*blk;

	xmalloc_ctx.allocated += size;
	XMALLOC_UPDATE(&xmalloc_ctx);

	if ((blk = xmalloc_find(NULL)) == NULL) {
		XMALLOC_PRINT("%s:%u: xmalloc_new: no space", file, line);
		return;
	}
	blk->ptr = ptr;
	blk->size = size;

	blk->file = file;
	blk->line = line;
}

void
xmalloc_change(const char *file, u_int line, void *oldptr, void *newptr,
    size_t newsize)
{
	struct xmalloc_blk	*blk;
	ssize_t			 change;

	if (oldptr == NULL) {
		xmalloc_new(file, line, newptr, newsize);
		return;
	}

	if ((blk = xmalloc_find(oldptr)) == NULL) {
		XMALLOC_PRINT("%s:%u: xmalloc_change: not found", file, line);
		return;
	}

	change = newsize - blk->size;
	if (change > 0)
		xmalloc_ctx.allocated += change;
	else
		xmalloc_ctx.freed -= change;
	XMALLOC_UPDATE(&xmalloc_ctx);

 	blk->ptr = newptr;
	blk->size = newsize;

	blk->file = file;
	blk->line = line;
}

void
xmalloc_free(const char *file, u_int line, void *ptr)
{
	struct xmalloc_blk	*blk;

	if ((blk = xmalloc_find(ptr)) == NULL) {
		XMALLOC_PRINT("%s:%u: xmalloc_free: not found", file, line);
		return;
	}

	xmalloc_ctx.freed += blk->size;

	blk->ptr = NULL;
}

void *
dxmalloc(const char *file, u_int line, size_t size)
{
	void	*ptr;

	ptr = xxmalloc(size);

	xmalloc_ctx.mallocs++;
	xmalloc_new(file, line, ptr, size);

	xmalloc_called(file, line, XMALLOC_MALLOC);

	return (ptr);
}

void *
dxcalloc(const char *file, u_int line, size_t nmemb, size_t size)
{
	void	*ptr;

	ptr = xxcalloc(nmemb, size);

	xmalloc_ctx.mallocs++;
	xmalloc_new(file, line, ptr, size);

	xmalloc_called(file, line, XMALLOC_MALLOC);

	return (ptr);
}

void *
dxrealloc(const char *file, u_int line, void *oldptr, size_t nmemb, size_t size)
{
	void	*newptr;

	newptr = xxrealloc(oldptr, nmemb, size);

	xmalloc_ctx.reallocs++;
	xmalloc_change(file, line, oldptr, newptr, nmemb * size);

	xmalloc_called(file, line, XMALLOC_REALLOC);

        return (newptr);
}

void
dxfree(const char *file, u_int line, void *ptr)
{
	xxfree(ptr);

	xmalloc_ctx.frees++;
	xmalloc_free(file, line, ptr);

	xmalloc_called(file, line, XMALLOC_FREE);
}

int printflike4
dxasprintf(const char *file, u_int line, char **ret, const char *fmt, ...)
{
	int	i;

        va_list ap;

        va_start(ap, fmt);
        i = dxvasprintf(file, line, ret, fmt, ap);
        va_end(ap);

	xmalloc_called(file, line, XMALLOC_MALLOC);

	return (i);
}

int
dxvasprintf(const char *file, u_int line, char **ret, const char *fmt,
    va_list ap)
{
	int	i;

	i = xxvasprintf(ret, fmt, ap);

	xmalloc_ctx.mallocs++;
	xmalloc_new(file, line, *ret, i);

	xmalloc_called(file, line, XMALLOC_MALLOC);

	return (i);
}

#endif /* DEBUG */
