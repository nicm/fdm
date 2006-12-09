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

#include <string.h>

#include "fdm.h"

int	command_match(struct match_ctx *, struct expritem *);
char   *command_desc(struct expritem *);

struct match match_command = { command_match, command_desc };

int
command_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct command_data	*data = ei->data;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct io		*io = mctx->io;
	struct msg		 msg;
	size_t			 slen;

	/* we are called as the child so to change uid this needs to be done
	   largely in the parent */
	msg.type = MSG_COMMAND;
	msg.data.account = a;
	msg.data.cmddata = data;
	msg.data.uid = data->uid;
	copy_mail(m, &msg.data.mail);
	slen = m->s != NULL ? strlen(m->s) : 0;
	if (privsep_send(io, &msg, m->s, slen) != 0)
		fatalx("child: privsep_send error");

	if (privsep_recv(io, &msg, NULL, 0) != 0)
		fatalx("child: privsep_recv error");
	if (msg.type != MSG_DONE)
		fatalx("child: unexpected message");

	return (msg.data.error);
}

char *
command_desc(struct expritem *ei)
{
	struct command_data	*data = ei->data;
	char			*s, ret[11];
	const char		*t;

	*ret = '\0';
	if (data->ret != -1)
		xsnprintf(ret, sizeof ret, "%d", data->ret);
	t = data->pipe ? "pipe" : "exec";

	if (data->re_s == NULL) {
		xasprintf(&s, "%s \"%s\" user %lu returns (%s, )", t,
		    data->cmd, (u_long) data->uid, ret);
		return (s);
	}

	xasprintf(&s, "command %s \"%s\" user %lu returns (%s, \"%s\")", t,
	    data->cmd, (u_long) data->uid, ret, data->re_s);
	return (s);
}
