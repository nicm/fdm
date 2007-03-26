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

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "match.h"

int	child_deliver(struct child *child, struct io *io);

int
child_deliver(struct child *child, struct io *io)
{
	struct child_deliver_data	*data = child->data;
	struct account			*a = data->account;
	struct mail			*m = data->mail;
	struct msg			 msg;
	struct msgbuf			 msgbuf;
	int				 error = 0;

#ifdef DEBUG
	xmalloc_clear();
	COUNTFDS(a->name);
#endif

	log_debug2("%s: deliver started, pid %ld", a->name, (long) getpid());

#ifndef NO_SETPROCTITLE
	setproctitle("%s[%lu]", data->name, (u_long) geteuid());
#endif

	/* refresh user and home and fix tags */
	fill_info(NULL);
	update_tags(&m->tags);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* call the hook */
	data->hook(0, a, &msg, data, &msg.data.error);

	/* inform parent we're done */
	msg.type = MSG_DONE;
	msg.id = 0;

	msgbuf.buf = m->tags;
	msgbuf.len = STRB_SIZE(m->tags);

	if (privsep_send(io, &msg, &msgbuf) != 0)
		fatalx("deliver: privsep_send error");
	if (privsep_recv(io, &msg, NULL) != 0)
		fatalx("deliver: privsep_recv error");
	if (msg.type != MSG_EXIT)
		fatalx("deliver: unexpected message");

#ifdef DEBUG
	COUNTFDS(a->name);
	xmalloc_report(a->name);
#endif 

	return (error);
}

void
child_deliver_action_hook(pid_t pid, struct account *a, struct msg *msg,
    struct child_deliver_data *data, int *result)
{
	struct action		*t = data->action;
	struct deliver_ctx	*dctx = data->dctx;
	struct mail		*m = data->mail;
	struct mail		*md = &dctx->wr_mail;

	/* check if this is the parent */
	if (pid != 0) {
		/* use new mail if necessary */
		if (t->deliver->type != DELIVER_WRBACK) {
			xfree(dctx);
			return;
		}

		if (*result != DELIVER_SUCCESS) {
			mail_destroy(md);

			xfree(dctx);
			return;
		}

		mail_close(md);
		if (mail_receive(m, msg, 0) != 0) {
			log_warn("parent_deliver: can't receive mail");
			*result = DELIVER_FAILURE;
		}

		xfree(dctx);
		return;
	}

	/* this is the child. do the delivery */
	*result = t->deliver->deliver(dctx, t);
	if (t->deliver->type != DELIVER_WRBACK || *result != DELIVER_SUCCESS)
		return;

	mail_send(md, msg);
	log_debug2("%s: using new mail, size %zu", a->name, md->size);
}

void
child_deliver_cmd_hook(pid_t pid, struct account *a, unused struct msg *msg,
    struct child_deliver_data *data, int *result)
{
	struct mail_ctx			*mctx = data->mctx;
	struct mail			*m = data->mail;
	struct match_command_data	*cmddata = data->cmddata;
	int				 flags, status, found = 0;
	char				*s, *cause, *lbuf, *out, *err, tag[24];
	size_t				 llen;
	struct cmd		 	*cmd = NULL;
	struct rmlist			 rml;
	u_int				 i;

	/* if this is the parent, do nothing */
	if (pid != 0) {
		xfree(mctx);
		return;
	}

	/* sort out the command */
	s = replacepath(&cmddata->cmd, m->tags, m, &m->rml);
        if (s == NULL || *s == '\0') {
		log_warnx("%s: empty command", a->name);
		goto error;
        }

	log_debug2("%s: %s: started (ret=%d re=%s)", a->name, s, cmddata->ret,
	    cmddata->re.str == NULL ? "none" : cmddata->re.str);
	flags = CMD_ONCE;
	if (cmddata->pipe)
		flags |= CMD_IN;
	if (cmddata->re.str != NULL)
		flags |= CMD_OUT;
	cmd = cmd_start(s, flags, conf.timeout, m->data, m->size, &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		goto error;
	}

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	do {
		/* stop early if looking for regexp only */
		if (found && cmddata->ret == -1) {
			log_debug3("%s: %s: found. stopping early", a->name, s);
			status = -1;
			break;
		}

		status = cmd_poll(cmd, &out, &err, &lbuf, &llen, &cause);
		if (status > 0) {
			log_warnx("%s: %s: %s", a->name, s, cause);
			goto error;
		}
       		if (status < 0)
			break;
		if (err != NULL)
			log_warnx("%s: %s: %s", a->name, s, err);
		if (out == NULL)
			continue;
		log_debug3("%s: %s: out: %s", a->name, s, out);
		if (found)
			continue;

		found = re_string(&cmddata->re, out, &rml, &cause);
		if (found == -1) {
			log_warnx("%s: %s", a->name, cause);
			goto error;
		}
		if (found != 1)
			continue;
		/* save the matches */
		if (!rml.valid)
			continue;
		for (i = 0; i < NPMATCH; i++) {
			if (!rml.list[i].valid)
				break;
			xsnprintf(tag, sizeof tag, "command%u", i);
			add_tag(&m->tags, tag, "%.*s", (int) (rml.list[i].eo -
			    rml.list[i].so), out + rml.list[i].so);
		}
	} while (status >= 0);
	status = -1 - status;

	log_debug2("%s: %s: returned %d, found %d", a->name, s, status, found);

	cmd_free(cmd);
	xfree(s);
	xfree(lbuf);

	status = cmddata->ret == status;
	if (cmddata->ret != -1 && cmddata->re.str != NULL)
		*result = (found && status) ? MATCH_TRUE : MATCH_FALSE;
	else if (cmddata->ret != -1 && cmddata->re.str == NULL)
		*result = status ? MATCH_TRUE : MATCH_FALSE;
	else if (cmddata->ret == -1 && cmddata->re.str != NULL)
		*result = found ? MATCH_TRUE : MATCH_FALSE;
	else
		*result = MATCH_ERROR;
	return;

error:
	if (cause != NULL)
		xfree(cause);
	if (cmd != NULL)
		cmd_free(cmd);
	if (s != NULL)
		xfree(s);
	if (lbuf != NULL)
		xfree(lbuf);
	*result = MATCH_ERROR;
}
