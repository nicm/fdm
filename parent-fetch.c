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
#include <sys/socket.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <paths.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "deliver.h"
#include "match.h"

void	parent_fetch_error(struct child *, struct msg *);
void	parent_fetch_action(struct child *, struct children *,
    	    struct deliver_ctx *, struct msg *);
void	parent_fetch_cmd(struct child *, struct children *, struct mail_ctx *,
	    struct msg *);

int
parent_fetch(struct child *child, struct msg *msg, struct msgbuf *msgbuf)
{
	struct child_fetch_data	*data = child->data;
	struct children		*children = data->children;
	struct deliver_ctx	*dctx;
	struct mail_ctx		*mctx;
	struct mail		*m;

	switch (msg->type) {
	case MSG_ACTION:
		if (msgbuf->buf == NULL || msgbuf->len == 0)
			fatalx("bad tags");
		m = xcalloc(1, sizeof *m);
		if (mail_receive(m, msg, 0) != 0) {
			log_warn("can't receive mail");
			parent_fetch_error(child, msg);
			break;
		}
		m->tags = msgbuf->buf;

		dctx = xcalloc(1, sizeof *dctx);
		dctx->account = msg->data.account;
		dctx->mail = m;

		parent_fetch_action(child, children, dctx, msg);
		break;
	case MSG_COMMAND:
		if (msgbuf->buf == NULL || msgbuf->len == 0)
			fatalx("bad tags");
		m = xcalloc(1, sizeof *m);
		if (mail_receive(m, msg, 0) != 0) {
			log_warn("can't receive mail");
			parent_fetch_error(child, msg);
			break;
		}
		m->tags = msgbuf->buf;

		mctx = xcalloc(1, sizeof *mctx);
		mctx->account = msg->data.account;
		mctx->mail = m;

		parent_fetch_cmd(child, children, mctx, msg);
		break;
	case MSG_DONE:
		fatalx("unexpected message");
	case MSG_EXIT:
		return (1);
	}

	return (0);
}

void
parent_fetch_error(struct child *child, struct msg *msg)
{
	msg->type = MSG_DONE;
	msg->data.error = DELIVER_FAILURE;
	if (privsep_send(child->io, msg, NULL) != 0)
		fatalx("privsep_send error");
}

void
parent_fetch_action(struct child *child, struct children *children,
    struct deliver_ctx *dctx, struct msg *msg)
{
	struct actitem			*ti = msg->data.actitem;
	uid_t				 uid = msg->data.uid;
	struct mail			*m = dctx->mail;
	struct mail			*md = &dctx->wr_mail;
	struct child_deliver_data	*data;

	memset(md, 0, sizeof *md);
	/*
	 * If writing back, open a new mail now and set its ownership so it
	 * can be accessed by the child.
	 */
	if (ti->deliver->type == DELIVER_WRBACK) {
		if (mail_open(md, IO_BLOCKSIZE) != 0) {
			log_warn("parent: failed to create mail");
			parent_fetch_error(child, msg);
			return;
		}
		if (geteuid() == 0 &&
		    shm_owner(&md->shm, conf.child_uid, conf.child_gid) != 0) {
			mail_destroy(md);
			log_warn("parent: failed to set mail ownership");
			parent_fetch_error(child, msg);
			return;
		}
		md->decision = m->decision;
	}

	data = xmalloc(sizeof *data);
	data->child = child;
	data->msgid = msg->id;
	data->account = dctx->account;
	data->hook = child_deliver_action_hook;
	data->actitem = ti;
	data->dctx = dctx;
	data->mail = m;
	data->name = "deliver";
	child = child_start(children, uid, child_deliver, parent_deliver, data);
	log_debug3("parent: deliver child %ld started", (long) child->pid);
}

void
parent_fetch_cmd(struct child *child, struct children *children,
    struct mail_ctx *mctx, struct msg *msg)
{
	uid_t				 uid = msg->data.uid;
	struct mail			*m = mctx->mail;
	struct child_deliver_data	*data;

	data = xmalloc(sizeof *data);
	data->child = child;
	data->msgid = msg->id;
	data->account = mctx->account;
	data->hook = child_deliver_cmd_hook;
	data->mctx = mctx;
	data->cmddata = msg->data.cmddata;
	data->mail = m;
	data->name = "command";
	child = child_start(children, uid, child_deliver, parent_deliver, data);
	log_debug3("parent: command child %ld started", (long) child->pid);
}
