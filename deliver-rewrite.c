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
#include "deliver.h"

int	 deliver_rewrite_deliver(struct deliver_ctx *, struct action *);
void	 deliver_rewrite_desc(struct action *, char *, size_t);

struct deliver deliver_rewrite = {
	"rewrite",
	DELIVER_WRBACK,
	deliver_rewrite_deliver,
	deliver_rewrite_desc
};

int
deliver_rewrite_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_rewrite_data	*data = t->data;
	struct mail			*md = &dctx->wr_mail;
        char				*s, *cause, *out, *err;
	size_t				 len;
	int	 			 status;
	struct cmd			*cmd;
	char				*lbuf;
	size_t				 llen;

	s = replacepath(&data->cmd, m->tags, m, &m->rml);
        if (s == NULL || *s == '\0') {
		log_warnx("%s: empty command", a->name);
		if (s != NULL)
			xfree(s);
                return (DELIVER_FAILURE);
        }

	log_debug2("%s: rewriting using \"%s\"", a->name, s);

	md->size = 0;

	cmd = cmd_start(s, CMD_IN|CMD_OUT|CMD_ONCE, conf.timeout, m->data,
	    m->size, &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		xfree(cause);
		goto error;
	}
	log_debug3("%s: %s: started", a->name, s);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	do {
		status = cmd_poll(cmd, &out, &err, &lbuf, &llen, &cause);
		if (status > 0) {
			log_warnx("%s: %s: %s", a->name, s, cause);
			xfree(cause);
			xfree(lbuf);
			goto error;
		}
       		if (status == 0) {
			if (err != NULL)
				log_warnx("%s: %s: %s", a->name, s, err);
			if (out != NULL) {
				log_debug3("%s: %s: out: %s", a->name, s, out);

				len = strlen(out);
				if (len == 0 && md->body == -1)
					md->body = md->size + 1;

				if (mail_resize(md, md->size + len + 1) != 0) {
					log_warn("%s: failed to resize mail",
					    a->name);
					goto error;
				}

				if (len > 0)
					memcpy(md->data + md->size, out, len);

				/* append an LF */
				md->data[md->size + len] = '\n';
				md->size += len + 1;
			}
		}
	} while (status >= 0);

	xfree(lbuf);

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

void
deliver_rewrite_desc(struct action *t, char *buf, size_t len)
{
	struct deliver_rewrite_data	*data = t->data;

	xsnprintf(buf, len, "rewrite \"%s\"", data->cmd.str);
}
