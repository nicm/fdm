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
#include <sys/wait.h>

#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	rewrite_deliver(struct account *, struct action *, struct mail *);

struct deliver deliver_rewrite = { "rewrite", DELIVER_WRBACK, rewrite_deliver };

int
rewrite_deliver(struct account *a, struct action *t, struct mail *m)
{
        char		*s, *cause, *out, *err;
	size_t		 len;
	struct mail	 m2;
	int	 	 status;
	struct cmd	*cmd;

	s = replaceinfo(t->data, a, t);
        if (s == NULL || *s == '\0') {
		log_warnx("%s: empty command", a->name);
		if (s != NULL)
			xfree(s);
                return (DELIVER_FAILURE);
        }

	log_debug("%s: rewriting using \"%s\"", a->name, s);

	memset(&m2, 0, sizeof m2);
	m2.space = IO_BLOCKSIZE;
	m2.base = m2.data = xmalloc(m2.space);
	m2.size = 0;
	m2.body = -1;

	cmd = cmd_start(s, 1, 1, m->data, m->size, &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		goto error;
	}

	do {
		status = cmd_poll(cmd, &out, &err, &cause);
		if (status > 0) {
			log_warnx("%s: %s: %s", a->name, s, cause);
			goto error;
		}
       		if (status == 0) {
			if (err != NULL) {
				log_warnx("%s: %s: %s", a->name, s, err);
				xfree(err);
			}
			if (out != NULL) {
				log_debug3("%s: %s: out: %s", a->name, s, out);

				len = strlen(out);
				if (len == 0 && m2.body == -1)
					m2.body = m2.size + 1;

				resize_mail(&m2, m2.size + len + 1);

				if (len > 0)
					memcpy(m2.data + m2.size, out, len);

				/* append an LF */
				m2.data[m2.size + len] = '\n';
				m2.size += len + 1;

				xfree(out);
			}
		}
	} while (status >= 0);

	status = -1 - status;
	if (status != 0) {
		log_warnx("%s: %s: command returned %d", a->name, s, status);
		goto error;
	} 

	if (m2.size == 0) {
		log_warnx("%s: %s: empty mail returned", a->name, s);
		goto error;
	}

	/* replace the old mail */
	free_mail(m);
	memcpy(m, &m2, sizeof *m);

	cmd_free(cmd);
	return (DELIVER_SUCCESS);

error:
	free_mail(&m2);

	cmd_free(cmd);
	return (DELIVER_FAILURE);
}
