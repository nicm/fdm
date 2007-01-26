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

struct xmalloc_ctx {
	size_t		 	 allocated;
	size_t		 	 freed;
	size_t		 	 peak;
	u_int		 	 frees;
	u_int		 	 mallocs;
	u_int		 	 reallocs;

	struct xmalloc_blk	 list[XMALLOC_SLOTS];
	struct xmalloc_call	 calls[XMALLOC_SLOTS];

};
struct xmalloc_ctx	 	 xmalloc_default;

#define XMALLOC_PRINT log_debug2

#define XMALLOC_PEEK 8
#define XMALLOC_LINES 32

#define XMALLOC_UPDATE(xctx) do {				\
	if (xctx->allocated - xctx->freed > xctx->peak)		\
		xctx->peak = xctx->allocated - xctx->freed;	\
} while (0)

void			 xmalloc_callrecord(struct xmalloc_ctx *, const char *,
    			     u_int, enum xmalloc_type);
struct xmalloc_blk	*xmalloc_find(struct xmalloc_ctx *, void *);
void			 xmalloc_new(struct xmalloc_ctx *, const char *,
			     u_int, void *, size_t);
void			 xmalloc_change(struct xmalloc_ctx *, const char *,
			     u_int, void *, void *, size_t);
void			 xmalloc_free(struct xmalloc_ctx *, const char *, u_int,
			     void *);

void
xmalloc_callrecord(struct xmalloc_ctx *xctx, const char *file, u_int line,
    enum xmalloc_type type)
{
	u_int	i;

	for (i = 0; i < XMALLOC_SLOTS; i++) {
		if (xctx->calls[i].type  == type && 
		    xctx->calls[i].line == line &&
		    strcmp(xctx->calls[i].file, file) == 0)
			break;
	}
	if (i == XMALLOC_SLOTS) {
		for (i = 0; i < XMALLOC_SLOTS; i++) {
			if (xctx->calls[i].type == XMALLOC_NONE)
				break;
		}
		if (i == XMALLOC_SLOTS)
			fatalx("xmalloc_callrecord: no space");
	}

	xctx->calls[i].type = type;
	xctx->calls[i].line = line;
	xctx->calls[i].file = file;
	xctx->calls[i].count++;
}

void
xmalloc_callreport(const char *hdr)
{
	struct xmalloc_ctx	*xctx = &xmalloc_default;
	u_int			 i;
	const char		*type = "";
	char			 fn[64];

	for (i = 0; i < XMALLOC_SLOTS; i++) {
		switch (xctx->calls[i].type) {
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

		xsnprintf(fn, sizeof fn, "%s:%u", xctx->calls[i].file,
		    xctx->calls[i].line);
		XMALLOC_PRINT("%s: %-10s %-24s %u", hdr, type, fn,
		    xctx->calls[i].count);
	}
}


struct xmalloc_blk *
xmalloc_find(struct xmalloc_ctx *xctx, void *ptr)
{
	u_int	i;

	for (i = 0; i < XMALLOC_SLOTS; i++) {
		if (xctx->list[i].ptr == ptr)
			return (&xctx->list[i]);
	}

	return (NULL);
}

void
xmalloc_clear(void)
{
	struct xmalloc_ctx	*xctx = &xmalloc_default;

	xctx->allocated = 0;
	xctx->freed = 0;
	xctx->peak = 0;
	xctx->frees = 0;
	xctx->mallocs = 0;
	xctx->reallocs = 0;

	memset(xctx->list, 0, sizeof xctx->list);
	memset(xctx->calls, 0, sizeof xctx->calls);
}

void
xmalloc_report(const char *hdr)
{
	struct xmalloc_ctx	*xctx = &xmalloc_default;
 	struct xmalloc_blk	*blk;
 	char	 		 line[256];
 	int			 len;
 	size_t	 		 off, size;
  	u_int	 		 i, j, n;

 	XMALLOC_PRINT("%s: allocated=%zu, freed=%zu, difference=%zd, peak=%zu",
 	    hdr, xctx->allocated, xctx->freed, xctx->allocated - xctx->freed,
	    xctx->peak);
 	XMALLOC_PRINT("%s: mallocs=%u, reallocs=%u, frees=%u", hdr,
	    xctx->mallocs, xctx->reallocs, xctx->frees);

	xmalloc_callreport(hdr);

 	if (xctx->allocated == xctx->freed)
 		return;

	n = 0;
	off = 0;
	for (i = 0; i < XMALLOC_SLOTS; i++) {
		blk = &xctx->list[i];
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
xmalloc_new(struct xmalloc_ctx *xctx, const char *file, u_int line, void *ptr,
    size_t size)
{
	struct xmalloc_blk	*blk;

	xctx->allocated += size;
	XMALLOC_UPDATE(xctx);

	if ((blk = xmalloc_find(xctx, NULL)) == NULL) {
		XMALLOC_PRINT("%s:%u: xmalloc_new: no space", file, line);
		return;
	}
	blk->ptr = ptr;
	blk->size = size;

	blk->file = file;
	blk->line = line;
}

void
xmalloc_change(struct xmalloc_ctx *xctx, const char *file, u_int line,
    void *oldptr, void *newptr, size_t newsize)
{
	struct xmalloc_blk	*blk;
	ssize_t			 change;

	if (oldptr == NULL) {
		xmalloc_new(xctx, file, line, newptr, newsize);
		return;
	}

	if ((blk = xmalloc_find(xctx, oldptr)) == NULL) {
		XMALLOC_PRINT("%s:%u: xmalloc_change: not found", file, line);
		return;
	}

	change = newsize - blk->size;
	if (change > 0)
		xctx->allocated += change;
	else
		xctx->freed -= change;
	XMALLOC_UPDATE(xctx);

 	blk->ptr = newptr;
	blk->size = newsize;

	blk->file = file;
	blk->line = line;
}

void
xmalloc_free(struct xmalloc_ctx *xctx, const char *file, u_int line, void *ptr)
{
	struct xmalloc_blk	*blk;

	if ((blk = xmalloc_find(xctx, ptr)) == NULL) {
		XMALLOC_PRINT("%s:%u: xmalloc_free: not found", file, line);
		return;
	}

	xctx->freed += blk->size;

	blk->ptr = NULL;
}

void *
dxmalloc(const char *file, u_int line, size_t size)
{
	void	*ptr;

	ptr = xxmalloc(size);

	xmalloc_default.mallocs++;
	xmalloc_new(&xmalloc_default, file, line, ptr, size);

	xmalloc_callrecord(&xmalloc_default, file, line, XMALLOC_MALLOC);

	return (ptr);
}

void *
dxcalloc(const char *file, u_int line, size_t nmemb, size_t size)
{
	void	*ptr;

	ptr = xxcalloc(nmemb, size);

	xmalloc_default.mallocs++;
	xmalloc_new(&xmalloc_default, file, line, ptr, size);

	xmalloc_callrecord(&xmalloc_default, file, line, XMALLOC_MALLOC);

	return (ptr);
}

void *
dxrealloc(const char *file, u_int line, void *oldptr, size_t nmemb, size_t size)
{
	void	*newptr;

	newptr = xxrealloc(oldptr, nmemb, size);

	xmalloc_default.reallocs++;
	xmalloc_change(&xmalloc_default, file, line, oldptr, newptr,
	    nmemb * size);

	xmalloc_callrecord(&xmalloc_default, file, line, XMALLOC_REALLOC);

        return (newptr);
}

void
dxfree(const char *file, u_int line, void *ptr)
{
	xxfree(ptr);

	xmalloc_default.frees++;
	xmalloc_free(&xmalloc_default, file, line, ptr);

	xmalloc_callrecord(&xmalloc_default, file, line, XMALLOC_FREE);
}

int printflike4
dxasprintf(const char *file, u_int line, char **ret, const char *fmt, ...)
{
	int	i;

        va_list ap;

        va_start(ap, fmt);
        i = dxvasprintf(file, line, ret, fmt, ap);
        va_end(ap);

	xmalloc_callrecord(&xmalloc_default, file, line, XMALLOC_MALLOC);

	return (i);
}

int
dxvasprintf(const char *file, u_int line, char **ret, const char *fmt,
    va_list ap)
{
	int	i;

	i = xxvasprintf(ret, fmt, ap);

	xmalloc_default.mallocs++;
	xmalloc_new(&xmalloc_default, file, line, *ret, i);

	xmalloc_callrecord(&xmalloc_default, file, line, XMALLOC_MALLOC);

	return (i);
}

#endif /* DEBUG */
