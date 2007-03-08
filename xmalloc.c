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
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fdm.h"

void *
ensure_for(void *buf, size_t *len, size_t size, size_t adj)
{
	if (adj == 0)
		fatalx("ensure_for: zero adj");

	if (SIZE_MAX - size < adj)
		fatalx("ensure_for: size + adj > SIZE_MAX");
	size += adj;

	if (*len == 0) {
		*len = BUFSIZ;
		buf = xmalloc(*len);
	}

	while (*len <= size) {
		buf = xrealloc(buf, 2, *len);
		*len *= 2;
	}

	return (buf);
}

void *
ensure_size(void *buf, size_t *len, size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		fatalx("ensure_size: zero size");
	if (SIZE_MAX / nmemb < size)
		fatalx("ensure_size: nmemb * size > SIZE_MAX");

	if (*len == 0) {
		*len = BUFSIZ;
		buf = xmalloc(*len);
	}

	while (*len <= nmemb * size) {
		buf = xrealloc(buf, 2, *len);
		*len *= 2;
	}

	return (buf);
}

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
xxcalloc(size_t nmemb, size_t size)
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
xxmalloc(size_t size)
{
        void	*ptr;

        if (size == 0)
                fatalx("xmalloc: zero size");
        if ((ptr = malloc(size)) == NULL)
		fatal("xmalloc");

        return (ptr);
}

void *
xxrealloc(void *oldptr, size_t nmemb, size_t size)
{
	size_t	 newsize = nmemb * size;
	void	*newptr;

	if (newsize == 0)
                fatalx("xrealloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("xrealloc: nmemb * size > SIZE_MAX");
        if ((newptr = realloc(oldptr, newsize)) == NULL)
		fatal("xrealloc");

        return (newptr);
}

void
xxfree(void *ptr)
{
	if (ptr == NULL)
		fatalx("xfree: null pointer");
	free(ptr);
}

int printflike2
xxasprintf(char **ret, const char *fmt, ...)
{
        va_list ap;
        int	i;

        va_start(ap, fmt);
        i = xxvasprintf(ret, fmt, ap);
        va_end(ap);

	return (i);
}

int
xxvasprintf(char **ret, const char *fmt, va_list ap)
{
	int	i;

	i = vasprintf(ret, fmt, ap);

        if (i < 0 || *ret == NULL)
                fatal("xvasprintf");

        return (i);
}

int printflike3
xsnprintf(char *buf, size_t len, const char *fmt, ...)
{
        va_list ap;
        int	i;

        va_start(ap, fmt);
        i = xvsnprintf(buf, len, fmt, ap);
        va_end(ap);

	return (i);
}

int
xvsnprintf(char *buf, size_t len, const char *fmt, va_list ap)
{
	int	i;

	if (len > INT_MAX) {
		errno = EINVAL;
		fatal("xvsnprintf");
	}

	i = vsnprintf(buf, len, fmt, ap);

        if (i < 0)
                fatal("xvsnprintf");

        return (i);
}

/*
 * Some system modify the path in place. This function avoids that.
 */
char *
xdirname(const char *src)
{
	char	dst[MAXPATHLEN];

	strlcpy(dst, src, sizeof dst);
	return (dirname(dst));
}

/*
 * Some system modify the path in place. This function avoids that.
 */
char *
xbasename(const char *src)
{
	char	dst[MAXPATHLEN];

	strlcpy(dst, src, sizeof dst);
	return (basename(dst));
}
