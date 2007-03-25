/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
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
#include <sys/stat.h>

#include <ctype.h>
#include <string.h>

#include "fdm.h"

int	netrc_token(FILE *, char **);

FILE *
netrc_open(const char *home, char **cause)
{
	char		 path[MAXPATHLEN];
	struct stat	 sb;
	FILE		*f;

	if (printpath(path, sizeof path, "%s/%s", home, ".netrc") != 0) {
		xasprintf(cause, "%s", strerror(errno));
		return (NULL);
	}

	if (stat(path, &sb) != 0) {
		xasprintf(cause, "%s: %s", path, strerror(errno));
		return (NULL);
	}
	if ((sb.st_mode & (sb.st_mode & (S_IROTH|S_IWOTH))) != 0) {
		xasprintf(cause, "%s: world readable or writable", path);
		return (NULL);
	}

	if ((f = fopen(path, "r")) == NULL) {
		xasprintf(cause, "%s: %s", path, strerror(errno));
		return (NULL);
	}

	return (f);
}

void
netrc_close(FILE *f)
{
	if (fclose(f) != 0)
		fatal("fclose");
}

int
netrc_lookup(FILE *f, const char *host, char **user, char **pass)
{
	char	*token;
	int	 found;

	if (user != NULL)
		*user = NULL;
	if (pass != NULL)
		*pass = NULL;

	found = 0;
	for (;;) {
		switch (netrc_token(f, &token)) {
		case 1:
			return (0);
		case -1:
			return (-1);
		}

		if (!found) {
			if (strcmp(token, "machine") == 0) {
				if (netrc_token(f, &token) != 0)
					return (-1);
				if (strcmp(token, host) == 0)
					found = 1;
			} else if (strcmp(token, "default") == 0)
				found = 1;
		} else {
			if (strcmp(token, "machine") == 0)
				break;
			if (strcmp(token, "default") == 0)
				break;

			if (user != NULL && strcmp(token, "login") == 0) {
				if (netrc_token(f, &token) != 0)
					return (-1);
				if (*token == '\0')
					return (-1);
				*user = xstrdup(token);
			}
			if (pass != NULL && strcmp(token, "password") == 0) {
				if (netrc_token(f, &token) != 0)
					return (-1);
				if (*token == '\0')
					return (-1);
				*pass = xstrdup(token);
			}
		}
	}

	return (0);
}

/*
 * Function below modified from token() in OpenBSD's usr.bin/ftp/ruserpass.c.
 *
 *	$OpenBSD: ruserpass.c,v 1.20 2006/05/16 23:43:16 ray Exp $
 *	$NetBSD: ruserpass.c,v 1.14 1997/07/20 09:46:01 lukem Exp $
 *
 * Copyright (c) 1985, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

int
netrc_token(FILE *f, char **cpp)
{
	static char	 token[BUFSIZ];
	char		*cp;
	int 		 c;

	if (feof(f) || ferror(f))
		return (1);

	while ((c = fgetc(f)) != EOF && (isspace(c) || c == ','))
		;
	if (c == EOF)
		return (1);

	cp = token;
	if (c == '"') {
		while ((c = fgetc(f)) != EOF && c != '"') {
			if (c == '\\' && (c = fgetc(f)) == EOF)
				break;
			*cp++ = c;
			if (cp == token + (sizeof token))
				return (-1);
		}
		if (c == EOF)	/* missing " */
			return (-1);
	} else {
		*cp++ = c;
		while ((c = fgetc(f)) != EOF && !isspace(c) && c != ',') {
			if (c == '\\' && (c = fgetc(f)) == EOF)
				break;
			*cp++ = c;
			if (cp == token + (sizeof token))
				return (-1);
		}
	}
	*cp = '\0';

	*cpp = token;
	return (0);
}
