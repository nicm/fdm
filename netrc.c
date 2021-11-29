/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicholas.marriott@gmail.com>
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

	if (ppath(path, sizeof path, "%s/%s", home, ".netrc") != 0) {
		xasprintf(cause, "%s", strerror(errno));
		return (NULL);
	}

	if (stat(path, &sb) != 0) {
		xasprintf(cause, "%s: %s", path, strerror(errno));
		return (NULL);
	}
	if ((sb.st_mode & (S_IROTH|S_IWOTH)) != 0) {
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
	fclose(f);
}

int
netrc_lookup(FILE *f, const char *host, char **user, char **pass)
{
	enum netrc_state {
		NETRC_NO_MACHINE_FOUND,
		NETRC_MACHINE_FOUND,
		NETRC_USER_FOUND,
	}	 state = NETRC_NO_MACHINE_FOUND;
	char	*token;
	int	 found = 0, found_default = 0, default_entries = 0;

	if (pass != NULL)
		*pass = NULL;

	for (;;) {
		switch (netrc_token(f, &token)) {
		case 1:
			return (0);
		case -1:
			return (-1);
		}

		switch (state) {
		case NETRC_NO_MACHINE_FOUND:
			if (strcmp(token, "machine") == 0) {
				if (netrc_token(f, &token) != 0)
					return (-1);
				if (strcmp(token, host) == 0)
					state = NETRC_MACHINE_FOUND;
			} else if (!found && strcmp(token, "default") == 0) {
				state = NETRC_MACHINE_FOUND;
				/* The line is a default entry. */
				found_default = 1;
			}
			continue;
		case NETRC_MACHINE_FOUND:
			if (strcmp(token, "login") != 0)
				continue;
			if (netrc_token(f, &token) != 0)
				return (-1);
			if (*token == '\0')
				return (-1);

			if (user != NULL && *user == NULL) {
				*user = xstrdup(token);
				state = NETRC_USER_FOUND;
				continue;
			}

			if (strcmp(token, *user) != 0)
				continue;
			if (!found) {
				/*
				 * We didn't find any matching host/user
				 * combination before and we are processing one
				 * so we advance to the next state.
				 */
				state = NETRC_USER_FOUND;
			} else if (found && !found_default) {
				/*
				 * We have the same host/user combination twice
				 * as we already found a host/user matching
				 * pair that is not a default entry and we're
				 * processing a second matching host/user pair.
				 */
				log_warnx("duplicate netrc entry with the same "
				    "login (%s) and machine", *user);
				return (-1);
			} else if (found &&
			    found_default &&
			    default_entries == 0) {
				/*
				 * Here we already have a valid host/user
				 * combination and we are processing a default
				 * entry line so we want to record the number
				 * of default/user to warn about duplicates.
				 */
				state = NETRC_NO_MACHINE_FOUND;
				found_default = 0;
				default_entries++;
			} else if (found &&
			    found_default == 1 &&
			    default_entries >= 1) {
				/*
				 * We are processing a matching default entry
				 * but we already processed a matching one
				 * before, so the current line is a duplicate.
				 */
				log_warnx("duplicate netrc entry with the same "
				    "login (%s) and 'default' machine", *user);
				return (-1);
			}
			continue;
		case NETRC_USER_FOUND:
			if (strcmp(token, "password") != 0)
				continue;
			if (netrc_token(f, &token) != 0)
				return (-1);
			if (*token == '\0')
				return (-1);

			*pass = xstrdup(token);

			/*
			 * We want to continue searching to make sure there is
			 * no other lines with the same host/user combination,
			 * else we would have to warn the user about it.
			 */
			state = NETRC_NO_MACHINE_FOUND;
			found++;

			if (found_default) {
				found_default = 0;

				/*
				 * This is so as to error if there are multiple
				 * matching default lines.
				 */
				default_entries++;
			}
			continue;
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
	int		 c;

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
