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

int	 rewrite_deliver(struct deliver_ctx *, struct action *);
char	*rewrite_desc(struct action *);

struct deliver deliver_rewrite = { DELIVER_WRBACK, rewrite_deliver,
				   rewrite_desc };

int
rewrite_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct account	*a = dctx->account;
	struct mail	*m = dctx->mail;
	struct mail	*md = &dctx->wr_mail;
        char		*s, *cause, *out, *err;
	size_t		 len;
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

	md->size = 0;

	log_debug2("%s: %s: starting", a->name, s);
	cmd = cmd_start(s, 1, 1, m->data, m->size, &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		goto error;
	}
	log_debug2("%s: %s: started", a->name, s);

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
				if (len == 0 && md->body == -1)
					md->body = md->size + 1;

				resize_mail(md, md->size + len + 1);

				if (len > 0)
					memcpy(md->data + md->size, out, len);

				/* append an LF */
				md->data[md->size + len] = '\n';
				md->size += len + 1;

				xfree(out);
			}
		}
	} while (status >= 0);

	status = -1 - status;
	if (status != 0) {
		log_warnx("%s: %s: command returned %d", a->name, s, status);
		goto error;
	} 

	if (md->size == 0) {
		log_warnx("%s: %s: empty mail returned", a->name, s);
		goto error;
	}

	cmd_free(cmd);
	xfree(s);
	return (DELIVER_SUCCESS);

error:
	cmd_free(cmd);
	xfree(s);
	return (DELIVER_FAILURE);
}

char *
rewrite_desc(struct action *t)
{
	char	*s;

	xasprintf(&s, "rewrite \"%s\"", (char *) t->data);
	return (s);
}
