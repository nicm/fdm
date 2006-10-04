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

struct xmalloc_block {
	void	*ptr;
	size_t	 size;
};
#define XMALLOC_SLOTS 1024
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
 	u_int	i;
	size_t	len, off;
	char	tmp[4096];

	log_debug("%s: allocated=%zu, freed=%zu", hdr, xmalloc_allocated,
	    xmalloc_freed);

	if (xmalloc_allocated == xmalloc_freed)
		return;

	len = 1024;
	off = xsnprintf(tmp, len, "%s: ", hdr);
	for (i = 0; i < XMALLOC_SLOTS; i++) {
		if (xmalloc_array[i].ptr != NULL) {
			off += xsnprintf(tmp + off, len - off, "[%p %zu] ",
			    xmalloc_array[i].ptr, xmalloc_array[i].size);
		}
	}
	tmp[off - 1] = '\0';
	log_debug("%s", tmp);
}

struct xmalloc_block *
xmalloc_find(void *ptr)
{
	u_int	i;

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
		log_warnx("xmalloc_free: not found");
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

#ifdef DEBUG
	xmalloc_new(ptr, len);
#endif

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
	xmalloc_new(*ret, i + 1);
#endif

        return (i);
}
