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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "deliver.h"

int	 deliver_pipe_deliver(struct deliver_ctx *, struct action *);
void	 deliver_pipe_desc(struct action *, char *, size_t);

struct deliver deliver_pipe = {
	"pipe",
	DELIVER_ASUSER,
	deliver_pipe_deliver,
	deliver_pipe_desc
};

int
deliver_pipe_deliver(struct deliver_ctx *dctx, struct action *t)
{
	return (do_pipe(dctx, t, 1));
}

void
deliver_pipe_desc(struct action *t, char *buf, size_t len)
{
	struct deliver_pipe_data	*data = t->data;

	xsnprintf(buf, len, "pipe \"%s\"", data->cmd.str);
}

int
do_pipe(struct deliver_ctx *dctx, struct action *t, int pipef)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_pipe_data	*data = t->data;
        char				*s, *cause, *err;
	int				 status;
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

	if (pipef)
		log_debug2("%s: piping to \"%s\"", a->name, s);
	else
		log_debug2("%s: executing \"%s\"", a->name, s);

	if (pipef) {
		cmd = cmd_start(s, CMD_IN|CMD_ONCE, conf.timeout, m->data,
		    m->size, &cause);
	} else
		cmd = cmd_start(s, 0, conf.timeout, NULL, 0, &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		xfree(cause);
		goto error;
	}
	log_debug3("%s: %s: started", a->name, s);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	do {
		status = cmd_poll(cmd, NULL, &err, &lbuf, &llen, &cause);
		if (status > 0) {
			log_warnx("%s: %s: %s", a->name, s, cause);
			xfree(cause);
			xfree(lbuf);
			goto error;
		}
       		if (status == 0) {
			if (err != NULL)
				log_warnx("%s: %s: %s", a->name, s, err);
		}
	} while (status >= 0);

	xfree(lbuf);

	status = -1 - status;
	if (status != 0) {
		log_warnx("%s: %s: command returned %d", a->name, s, status);
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
