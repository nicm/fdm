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

int
parent_deliver(struct child *child, struct msg *msg, struct msgbuf *msgbuf)
{
	struct child_deliver_data	*data = child->data;
	struct account			*a = data->account;
	struct mail			*m = data->mail;

	switch (msg->type) {
	case MSG_DONE:
		break;
	default:
		fatalx("parent_deliver: unexpected message");
	}

	if (msgbuf->buf == NULL || msgbuf->len == 0)
		fatalx("parent_deliver: bad tags");
	strb_destroy(&m->tags);
	m->tags = msgbuf->buf;

	/* call the hook */
	data->hook(1, a, msg, data, &msg->data.error);

	msg->type = MSG_DONE;
	msg->id = data->msgid;

	msgbuf->buf = m->tags;
	msgbuf->len = STRB_SIZE(m->tags);

	mail_send(m, msg);

	child = data->child;
	if (privsep_send(child->io, msg, msgbuf) != 0)
		fatalx("parent_deliver: privsep_send error");

	mail_close(m);
	xfree(m);

	return (1);
}
