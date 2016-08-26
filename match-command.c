/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicholas.marriott@gmail.com>
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
#include "match.h"

int	match_command_match(struct mail_ctx *, struct expritem *);
void	match_command_desc(struct expritem *, char *, size_t);

struct match match_command = {
	"command",
	match_command_match,
	match_command_desc
};

int
match_command_match(struct mail_ctx *mctx, struct expritem *ei)
{
	struct match_command_data	*data = ei->data;
	struct account			*a = mctx->account;
	struct mail			*m = mctx->mail;
	struct io			*io = mctx->io;
	struct msg			 msg;
	struct msgbuf			 msgbuf;
	struct userdata			*ud;
	char				*user;

	set_wrapped(m, '\n');

	/*
	 * We are called as the child so to change uid this needs to be done
	 * largely in the parent.
	 */
	memset(&msg, 0, sizeof msg);
	msg.type = MSG_COMMAND;
	msg.id = m->idx;

	msg.data.account = a;
	msg.data.cmddata = data;

	user = conf.cmd_user;
	if (data->user.str != NULL)
		user = replacestr(&data->user, m->tags, m, &m->rml);
	if ((ud = user_lookup(user, conf.user_order)) == NULL) {
		log_warnx("%s: bad user: %s", a->name, user);
		return (MATCH_ERROR);
	}
	if (data->user.str != NULL)
		xfree(user);

	msg.data.uid = ud->uid;
	msg.data.gid = ud->gid;
	update_tags(&m->tags, ud);
	user_free(ud);

	msgbuf.buf = m->tags;
	msgbuf.len = STRB_SIZE(m->tags);

	mail_send(m, &msg);

	if (privsep_send(io, &msg, &msgbuf) != 0)
		fatalx("privsep_send error");

	reset_tags(&m->tags);

	mctx->msgid = msg.id;
	return (MATCH_PARENT);
}

void
match_command_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_command_data	*data = ei->data;
	char				ret[11];
	const char			*type;

	*ret = '\0';
	if (data->ret != -1)
		xsnprintf(ret, sizeof ret, "%d", data->ret);
	type = data->pipe ? "pipe" : "exec";

	if (data->re.str == NULL) {
		if (data->user.str != NULL) {
			xsnprintf(buf, len,
			    "%s \"%s\" user \"%s\" returns (%s, )",
			    type, data->cmd.str, data->user.str, ret);
		} else {
			xsnprintf(buf, len, "%s \"%s\" returns (%s, )", type,
			    data->cmd.str, ret);
		}
	} else {
		if (data->user.str != NULL) {
			xsnprintf(buf, len,
			    "%s \"%s\" user \"%s\" returns (%s, \"%s\")",
			    type, data->cmd.str, data->user.str, ret,
			    data->re.str);
		} else {
			xsnprintf(buf, len,
			    "%s \"%s\" returns (%s, \"%s\")",
			    type, data->cmd.str, ret, data->re.str);
		}
	}
}
