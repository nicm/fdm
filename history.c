/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <fnmatch.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

/* Reload history. */
int
load_hist(FILE *f)
{
	struct account	*a;
	char		 name[MAXNAMESIZE], fmt[32], ch;
	size_t		 len;

	if (fseeko(f, 0, SEEK_SET) != 0)
		return (1);

	while (!feof(f)) {
		if (fscanf(f, "%zu ", &len) != 1)
			return (1);
		if (len >= sizeof name)
			return (1);

		if (xsnprintf(fmt, sizeof fmt, "%%%zuc ", len) < 0)
			return (1);
		if (fscanf(f, fmt, name) != 1)
			return (1);
		name[len] = '\0';
		
		TAILQ_FOREACH(a, &conf.accounts, entry) {
			if (strcmp(name, a->name) == 0)
				break;
		}
		if (a == TAILQ_END(&conf.accounts)) {
			do {
				ch = fgetc(f);
			} while (ch != EOF && ch != '\n');
			if (ch == EOF)
				return (1);
			continue;
		}

		if (fscanf(f, "%d %u %u %llu\n", &a->hist.since, &a->hist.runs,
		    &a->hist.mails, &a->hist.bytes) != 4)
			return (1);
	}
	
	return (0);
}

/* Save history. Doing this atomically would be nice, but it is sacrificed to 
   the greater good of privsep. */
int
save_hist(FILE *f)
{
	struct account	*a;

	if (ftruncate(fileno(f), 0) != 0)
		return (1);
	if (fseeko(f, 0, SEEK_SET) != 0)
		return (1);

	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (fprintf(f, "%zu %s %d %u %u %llu\n",
		    strlen(a->name), a->name, a->hist.since, a->hist.runs,
		    a->hist.mails, a->hist.bytes) == -1)
			return (1);
	}

	return (0);
}

/* Dump history to stdout. */
void
dump_hist(void)
{
	struct account	*a;
	char		*since, *ptr;

	printf("%-24s%-26s%8s%8s%12s\n",
	    "Account", "Since", "Times", "Mails", "Bytes");

	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (!check_incl(a->name)) {
			log_debug("account %s is not included", a->name);
			continue;
		}
		if (check_excl(a->name)) {
			log_debug("account %s is excluded", a->name);
			continue;
		}

		if (a->hist.since == 0)
			since = "never";
		else {
			since = ctime(&a->hist.since);
			if ((ptr = strchr(since, '\n')) != NULL)
				*ptr = '\0';
		}

		printf("%-24s%-26.26s%8u%8u%12llu\n",
		    a->name, since, a->hist.runs, a->hist.mails, a->hist.bytes);
	}

	fflush(stdout);
}
