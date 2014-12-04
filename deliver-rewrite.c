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

int	 deliver_rewrite_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_rewrite_desc(struct actitem *, char *, size_t);

struct deliver deliver_rewrite = {
	"rewrite",
	DELIVER_WRBACK,
	deliver_rewrite_deliver,
	deliver_rewrite_desc
};

int
deliver_rewrite_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_rewrite_data	*data = ti->data;
	struct mail			*md = &dctx->wr_mail;
	char				*s, *cause, *out, *err;
	int				 status;
	struct cmd			*cmd = NULL;
	char				*lbuf;
	size_t				 llen;

	s = replacepath(&data->cmd, m->tags, m, &m->rml, dctx->udata->home);
	if (s == NULL || *s == '\0') {
		log_warnx("%s: empty command", a->name);
		goto error;
	}

	log_debug2("%s: rewriting using \"%s\"", a->name, s);

	md->size = 0;

	cmd = cmd_start(s, CMD_IN|CMD_OUT|CMD_ONCE, m->data, m->size, &cause);
	if (cmd == NULL)
		goto error_cause;
	log_debug3("%s: %s: started", a->name, s);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	do {
		status = cmd_poll(
		    cmd, &out, &err, &lbuf, &llen, conf.timeout, &cause);
		if (status == -1) {
			xfree(lbuf);
			goto error_cause;
		}
		if (status != 0)
			continue;
		if (err != NULL)
			log_warnx("%s: %s: %s", a->name, s, err);
		if (out == NULL)
			continue;
		log_debug3("%s: %s: out: %s", a->name, s, out);

		if (append_line(md, out, strlen(out)) != 0) {
			log_warnx("%s: %s: failed to resize mail", s, a->name);
			goto error;
		}
		if (md->size > conf.max_size) {
			log_warnx("%s: %s: oversize mail returned", s, a->name);
			goto error;
		}
	} while (status == 0);
	status--;

	xfree(lbuf);

	if (status != 0) {
		log_warnx("%s: %s: command returned %d", a->name, s, status);
		goto error;
	}

	if (md->size == 0) {
		log_warnx("%s: %s: empty mail returned", a->name, s);
		goto error;
	}
	md->body = find_body(md);

	cmd_free(cmd);
	xfree(s);
	return (DELIVER_SUCCESS);

error_cause:
	log_warnx("%s: %s: %s", a->name, s, cause);
	xfree(cause);

error:
	if (cmd != NULL)
		cmd_free(cmd);
	if (s != NULL)
		xfree(s);
	return (DELIVER_FAILURE);
}

void
deliver_rewrite_desc(struct actitem *ti, char *buf, size_t len)
{
	struct deliver_rewrite_data	*data = ti->data;

	xsnprintf(buf, len, "rewrite \"%s\"", data->cmd.str);
}
