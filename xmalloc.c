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
#include <stdlib.h>
#include <string.h>

#include "fdm.h"

char *
xstrdup(const char *s)
{
	size_t	len;

	len = strlen(s) + 1;
        return (strncpy(xmalloc(len), s, len));
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
        return (ptr);
}

void *
xrealloc(void *ptr, size_t nmemb, size_t size)
{
	size_t new_size = nmemb * size;

	if (new_size == 0)
                fatalx("xrealloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("xrealloc: nmemb * size > SIZE_MAX");
        if ((ptr = realloc(ptr, new_size)) == NULL)
		fatal("xrealloc");
        return (ptr);
}

void
xfree(void *ptr)
{
	if (ptr == NULL)
		fatalx("xfree: null pointer");
	free(ptr);
}

int
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

int
xasprintf(char **ret, const char *fmt, ...)
{
        va_list ap;
        int	i;

        va_start(ap, fmt);
        i = vasprintf(ret, fmt, ap);
        va_end(ap);

        if (i < 0 || *ret == NULL)
                fatal("xasprintf");

        return (i);
}
