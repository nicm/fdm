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

struct match match_command = { "command", command_match, command_desc };

int
command_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct command_data	*data;
	struct msg		 msg;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct io		*io = mctx->io;

	data = ei->data;

	/* we are called as the child so to change uid this needs to be dond
	   largely in the parent */
	msg.type = MSG_COMMAND;
	msg.data.account = a;
	msg.data.cmddata = data;
	msg.data.uid = data->uid;
	memcpy(&msg.data.mail, m, sizeof msg.data.mail);
	if (privsep_send(io, &msg, m->data, m->size) != 0)
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
	struct command_data	*data;
	char			*s, ret[11];
	const char		*t;

	data = ei->data;

	*ret = '\0';
	if (data->ret != -1)
		snprintf(ret, sizeof ret, "%d", data->ret);
	t = data->pipe ? "pipe" : "exec";

	if (data->re_s == NULL) {
		xasprintf(&s, "%s \"%s\" returns (%s, )", t, data->cmd, ret);
		return (s);
	}

	xasprintf(&s, "%s \"%s\" returns (%s, \"%s\")", t, data->cmd, ret,
	    data->re_s);
	return (s);
}
