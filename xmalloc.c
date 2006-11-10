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

#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fdm.h"

#ifdef DEBUG
size_t	xmalloc_allocated;
size_t	xmalloc_freed;
size_t	xmalloc_peak;
u_int	xmalloc_frees;
u_int	xmalloc_mallocs;
u_int	xmalloc_reallocs;

struct xmalloc_block {
	void	*ptr;
	size_t	 size;
};
#define XMALLOC_SLOTS 8192
struct xmalloc_block	 xmalloc_array[XMALLOC_SLOTS];

struct xmalloc_block	*xmalloc_find(void *);
void			 xmalloc_new(void *, size_t);
void			 xmalloc_change(void *, void *, size_t);
void			 xmalloc_free(void *);

void
xmalloc_clear(void)
{
 	u_int	i;

	xmalloc_allocated = 0;
	xmalloc_freed = 0;

	for (i = 0; i < XMALLOC_SLOTS; i++)
		xmalloc_array[i].ptr = NULL;
}

void
xmalloc_dump(char *hdr)
{
 	u_int	 		 i, j, n = 0;
	int	 		 off, off2;
	size_t	 		 len;
	char	 		 tmp[4096];
	struct xmalloc_block	*p;
	
	log_debug("%s: allocated=%zu, freed=%zu, difference=%zd, peak=%zd", hdr,
	    xmalloc_allocated, xmalloc_freed,
	    xmalloc_allocated - xmalloc_freed, xmalloc_peak);
	log_debug("%s: mallocs=%u, reallocs=%u, frees=%u", hdr,
	    xmalloc_mallocs, xmalloc_reallocs, xmalloc_frees);

	if (xmalloc_allocated == xmalloc_freed)
		return;

	len = sizeof tmp;
	if ((off = xsnprintf(tmp, len, "%s: ", hdr)) < 0)
		fatal("xsnprintf");
	for (i = 0; i < XMALLOC_SLOTS; i++) {
		n++;
		if (n > 64)
			break;

		p = &xmalloc_array[i];
		if (p->ptr != NULL) {
			off2 = xsnprintf(tmp + off, len - off, "[%p %zu:",
			    p->ptr, p->size);
			if (off2 < 0)
				fatal("xsnprintf");
			off += off2;

			for (j = 0; j < (p->size > 8 ? 8 : p->size); j++) {
				if (((char *) p->ptr)[j] > 31) {
					off2 = xsnprintf(tmp + off, len - off,
					    "%c", ((char *) p->ptr)[j]);
				} else {
					off2 = xsnprintf(tmp + off, len - off,
					    "\\%03o", ((char *) p->ptr)[j]);
				}
				if (off2 < 0)
					fatal("xsnprintf");
				off += off2;
			}

			off2 = xsnprintf(tmp + off, len - off, "] ");
			if (off2 < 0)
				fatal("xsnprintf");
			off += off2;
		}
	}
	tmp[off - 1] = '\0';
	log_debug("%s", tmp);
}

struct xmalloc_block *
xmalloc_find(void *ptr)
{
	u_int	i;

	/* XXX */
	if (xmalloc_allocated - xmalloc_freed > xmalloc_peak)
		xmalloc_peak = xmalloc_allocated - xmalloc_freed;

	for (i = 0; i < XMALLOC_SLOTS; i++) {
		if (xmalloc_array[i].ptr == ptr)
			return (&xmalloc_array[i]);
	}
	return (NULL);
}

void
xmalloc_new(void *ptr, size_t size)
{
	struct xmalloc_block	*block;

#if 0
	log_debug3("xmalloc_new: %p %zu", ptr, size);
#endif

	if ((block = xmalloc_find(NULL)) == NULL) {
		log_warnx("xmalloc_new: no space");
		abort();
	}

	block->ptr = ptr;
	block->size = size;

	xmalloc_allocated += size;
}

void
xmalloc_change(void *oldptr, void *newptr, size_t newsize)
{
	struct xmalloc_block	*block;
	ssize_t			 change;

#if 0
	log_debug3("xmalloc_change: %p -> %p %zu", oldptr, newptr, newsize);
#endif

	if (oldptr == NULL) {
		xmalloc_new(newptr, newsize);
		return;
	}
		
	if ((block = xmalloc_find(oldptr)) == NULL) {
		log_warnx("xmalloc_change: not found");
		abort();
	}

	change = newsize - block->size;
	if (change > 0)
		xmalloc_allocated += change;
	else
		xmalloc_freed -= change;

	block->ptr = newptr;
	block->size = newsize;
}

void
xmalloc_free(void *ptr)
{
	struct xmalloc_block	*block;

#if 0
	log_debug3("xmalloc_free: %p", ptr);
#endif
	if ((block = xmalloc_find(ptr)) == NULL) {
		log_warnx("xmalloc_free: not found (%p)", ptr);
		return;
	}

	xmalloc_freed += block->size;

	block->ptr = NULL;
}

#endif /* DEBUG */

char *
xstrdup(const char *s)
{
	void	*ptr;
	size_t	 len;

	len = strlen(s) + 1;
	ptr = xmalloc(len);

        return (strncpy(ptr, s, len));
}

void *
xcalloc(size_t nmemb, size_t size)
{
        void	*ptr;

        if (size == 0 || nmemb == 0)
                fatalx("xcalloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("xcalloc: nmemb * size > SIZE_MAX");
        if ((ptr = calloc(nmemb, size)) == NULL)
		fatal("xcalloc");

#ifdef DEBUG
	xmalloc_mallocs++;
	xmalloc_new(ptr, nmemb * size);
#endif

        return (ptr);
}

void *
xmalloc(size_t size)
{
        void	*ptr;

        if (size == 0)
                fatalx("xmalloc: zero size");
        if ((ptr = malloc(size)) == NULL)
		fatal("xmalloc");

#ifdef DEBUG
	xmalloc_mallocs++;
	xmalloc_new(ptr, size);
#endif

        return (ptr);
}

void *
xrealloc(void *oldptr, size_t nmemb, size_t size)
{
	size_t	 newsize = nmemb * size;
	void	*newptr;

	if (newsize == 0)
                fatalx("xrealloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("xrealloc: nmemb * size > SIZE_MAX");
        if ((newptr = realloc(oldptr, newsize)) == NULL)
		fatal("xrealloc");

#ifdef DEBUG
	xmalloc_reallocs++;
	xmalloc_change(oldptr, newptr, newsize);
#endif

        return (newptr);
}

void
xfree(void *ptr)
{
	if (ptr == NULL)
		fatalx("xfree: null pointer");
	free(ptr);

#ifdef DEBUG
	xmalloc_frees++;
	xmalloc_free(ptr);
#endif
}

int printflike3
xsnprintf(char *str, size_t size, const char *fmt, ...)
{
	int	i;

	va_list	ap;

	va_start(ap, fmt);
	i = vsnprintf(str, size, fmt, ap);
	va_end(ap);

	if (i > 0 && (size_t) i >= size) {	/* truncation is failure */
		i = -1;
		errno = EINVAL;
	}

	return (i);
}

int printflike2
xasprintf(char **ret, const char *fmt, ...)
{
        va_list ap;
        int	i;

        va_start(ap, fmt);
        i = vasprintf(ret, fmt, ap);
        va_end(ap);

        if (i < 0 || *ret == NULL)
                fatal("xasprintf");

#ifdef DEBUG
	xmalloc_mallocs++;
	xmalloc_new(*ret, i + 1);
#endif

        return (i);
}
