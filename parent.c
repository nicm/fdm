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

int	parent_action(struct action *, struct deliver_ctx *, uid_t);
int	parent_command(struct match_ctx *, struct match_command_data *, uid_t);

int
do_parent(struct child *child)
{
	struct msg	 	 msg;
	struct msgdata		*data;
	struct deliver_ctx	 dctx;
	struct match_ctx	 mctx;
	struct mail		 m;
	int			 error;
	uid_t			 uid;
	void			*buf;
	size_t			 len;

	memset(&m, 0, sizeof m);
	data = &msg.data;

	if (privsep_recv(child->io, &msg, &buf, &len) != 0)
		fatalx("parent: privsep_recv error");
	log_debug2("parent: got message type %d from child %ld (%s)", msg.type,
	    (long) child->pid, child->account->name);

	switch (msg.type) {
	case MSG_ACTION:
		mail_receive(&m, &msg);
		if (buf == NULL || len == 0)
			fatalx("parent: bad tags");
		m.tags = buf;

		uid = data->uid;
		memset(&dctx, 0, sizeof dctx);
		dctx.account = data->account;
		dctx.mail = &m;
		dctx.decision = NULL;	/* only altered in child */
		dctx.pm_valid = &msg.data.pm_valid;
		memcpy(&dctx.pm, &msg.data.pm, sizeof dctx.pm);

		error = parent_action(data->action, &dctx, uid);

		memset(&msg, 0, sizeof msg);
		msg.type = MSG_DONE;
		msg.data.error = error;
		mail_send(&m, &msg);
		if (privsep_send(child->io, &msg, m.tags,
		    STRB_SIZE(m.tags)) != 0)
			fatalx("parent: privsep_send error");

		mail_close(&m);
		break;
	case MSG_COMMAND:
		mail_receive(&m, &msg);
		if (buf == NULL || len == 0)
			fatalx("parent: bad tags");
		m.tags = buf;

		uid = data->uid;
		memset(&mctx, 0, sizeof mctx);
		mctx.account = data->account;
		mctx.mail = &m;
		mctx.pm_valid = msg.data.pm_valid;
		memcpy(&mctx.pm, &msg.data.pm, sizeof mctx.pm);

		error = parent_command(&mctx, data->cmddata, uid);

		memset(&msg, 0, sizeof msg);
		msg.type = MSG_DONE;
		msg.data.error = error;
		if (privsep_send(child->io, &msg, 0, NULL) != 0)
			fatalx("parent: privsep_send error");

		mail_close(&m);
		break;
	case MSG_DONE:
		fatalx("parent: unexpected message");
	case MSG_EXIT:
		return (1);
	}

	return (0);
}

int
parent_action(struct action *t, struct deliver_ctx *dctx, uid_t uid)
{
	struct account		*a = dctx->account;
	struct mail		*m = dctx->mail;
	int		 	 status, error, fds[2];
	pid_t		 	 pid;
	struct io		*io;
	struct msg	 	 msg;
	void			*buf;
	size_t			 len;

	memset(&dctx->wr_mail, 0, sizeof dctx->wr_mail);
	/* if writing back, open a new mail now and set its ownership so it
	   can be accessed by the child */
	if (t->deliver->type == DELIVER_WRBACK) {
		mail_open(&dctx->wr_mail, IO_BLOCKSIZE);
		if (geteuid() == 0 && fchown(dctx->wr_mail.shm.fd,
		    conf.child_uid, conf.child_gid) != 0)
			fatal("fchown");
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, fds) != 0)
		fatal("socketpair");
	pid = child_fork();
	if (pid != 0) {
		/* create privsep io */
		close(fds[1]);
		io = io_create(fds[0], NULL, IO_LF, INFTIM);

 		/* parent process. wait for child */
		log_debug2("%s: forked. child pid is %ld", a->name, (long) pid);

		do {
			if (privsep_recv(io, &msg, &buf, &len) != 0)
				fatalx("parent2: privsep_recv error");
			log_debug2("parent2: got message type %d", msg.type);

			switch (msg.type) {
			case MSG_DONE:
				break;
			default:
				fatalx("parent2: unexpected message");
			}
		} while (msg.type != MSG_DONE);
		error = msg.data.error;

		if (buf == NULL || len == 0)
			fatalx("parent2: bad tags");
		strb_destroy(&m->tags);
		m->tags = buf;

		/* use new mail if necessary */
		if (t->deliver->type == DELIVER_WRBACK) {
			if (error == DELIVER_SUCCESS) {
				mail_close(&dctx->wr_mail);

				mail_receive(m, &msg);
				log_debug2("%s: got new mail from delivery: "
				    "size %zu, body %zd", a->name, m->size,
				    m->body);
			} else
				mail_destroy(&dctx->wr_mail);
		}

		/* free the io */
		io_close(io);
		io_free(io);

		if (waitpid(pid, &status, 0) == -1)
			fatal("waitpid");
		if (WIFSIGNALED(status)) {
			log_warnx("%s: child got signal: %d", a->name,
			    WTERMSIG(status));
			return (DELIVER_FAILURE);
		}
		if (!WIFEXITED(status)) {
			log_warnx("%s: child didn't exit normally", a->name);
			return (DELIVER_FAILURE);
		}
		status = WEXITSTATUS(status);
		if (status != 0) {
			log_warnx("%s: child returned %d", a->name, status);
			return (DELIVER_FAILURE);
		}

		return (error);
	}

#ifdef DEBUG
	xmalloc_clear();
	COUNTFDS(a->name);
#endif

	/* create privsep io */
 	close(fds[0]);
	io = io_create(fds[1], NULL, IO_LF, INFTIM);

	/* child process. change user and group */
	log_debug("%s: trying to deliver using uid %lu", a->name, (u_long) uid);
	if (geteuid() == 0) {
		if (dropto(uid) != 0) {
			log_warnx("%s: can't drop privileges", a->name);
			child_exit(DELIVER_FAILURE);
		}
	} else {
		log_debug("%s: not root. using current user", a->name);
		uid = geteuid();
	}
#ifndef NO_SETPROCTITLE
	setproctitle("deliver[%lu]", (u_long) uid);
#endif

	/* refresh user and home and fix tags */
	fill_info(NULL);
	update_tags(&m->tags);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* do the delivery */
	error = t->deliver->deliver(dctx, t);
	if (t->deliver->type == DELIVER_WRBACK && error == DELIVER_SUCCESS) {
		log_debug2("%s: using new mail, size %zu", a->name,
		    dctx->wr_mail.size);
		mail_send(&dctx->wr_mail, &msg);
	}

	/* inform parent we're done */
	msg.type = MSG_DONE;
	msg.data.error = error;
	if (privsep_send(io, &msg, m->tags, STRB_SIZE(m->tags)) != 0)
		fatalx("deliver: privsep_send error");

	/* free the io */
	io_close(io);
	io_free(io);

#ifdef DEBUG
	COUNTFDS(a->name);
	xmalloc_report(a->name);
#endif

	child_exit(0);
	return (DELIVER_FAILURE);
}

int
parent_command(struct match_ctx *mctx, struct match_command_data *data,
    uid_t uid)
{
	struct account	*a = mctx->account;
	struct mail	*m = mctx->mail;
	int		 status, found, flags;
	pid_t		 pid;
	char		*s, *cause, *out, *err;
	struct cmd	*cmd;
	char		*lbuf;
	size_t		 llen;

	pid = child_fork();
	if (pid != 0) {
 		/* parent process. wait for child */
		log_debug2("%s: forked. child pid is %ld", a->name, (long) pid);

		if (waitpid(pid, &status, 0) == -1)
			fatal("waitpid");
		if (WIFSIGNALED(status)) {
			log_warnx("%s: child got signal: %d", a->name,
			    WTERMSIG(status));
			return (MATCH_ERROR);
		}
		if (!WIFEXITED(status)) {
			log_warnx("%s: child didn't exit normally", a->name);
			return (MATCH_ERROR);
		}
		status = WEXITSTATUS(status);
		switch (status) {
		case MATCH_FALSE:
		case MATCH_TRUE:
		case MATCH_ERROR:
			return (status);
		default:
			return (MATCH_ERROR);
		}
	}

	/* child process. change user and group */
	log_debug("%s: trying to run command \"%s\" as uid %lu", a->name,
	    data->cmd, (u_long) uid);
	if (geteuid() == 0) {
		if (dropto(uid) != 0) {
			log_warnx("%s: can't drop privileges", a->name);
			child_exit(MATCH_ERROR);
		}
	} else
		log_debug("%s: not root. using current user", a->name);
#ifndef NO_SETPROCTITLE
	setproctitle("command[%lu]", (u_long) uid);
#endif

	/* refresh user and home and fix tags */
	fill_info(NULL);
	update_tags(&m->tags);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* sort out the command */
	s = replace(data->cmd, m->tags, m, mctx->pm_valid, mctx->pm);
        if (s == NULL || *s == '\0') {
		log_warnx("%s: empty command", a->name);
		child_exit(MATCH_ERROR);
        }

	log_debug2("%s: %s: started (ret=%d re=%s)", a->name, s, data->ret,
	    data->re.str == NULL ? "none" : data->re.str);
	flags = CMD_ONCE;
	if (data->pipe)
		flags |= CMD_IN;
	if (data->re.str != NULL)
		flags |= CMD_OUT;
	cmd = cmd_start(s, flags, m->data, m->size, &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		xfree(cause);
		xfree(s);
		child_exit(MATCH_ERROR);
	}

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	found = 0;
	do {
		status = cmd_poll(cmd, &out, &err, &lbuf, &llen, &cause);
		if (status > 0) {
			log_warnx("%s: %s: %s", a->name, s, cause);
			xfree(cause);
			cmd_free(cmd);
			xfree(s);
			xfree(lbuf);
			child_exit(MATCH_ERROR);
		}
       		if (status == 0) {
			if (err != NULL)
				log_warnx("%s: %s: %s", a->name, s, err);
			if (out != NULL) {
				log_debug3("%s: %s: out: %s", a->name, s, out);

				found = re_simple(&data->re, out, &cause);
				if (found == -1) {
					log_warnx("%s: %s", a->name, cause);
					cmd_free(cmd);
					xfree(s);
					xfree(lbuf);
					child_exit(MATCH_ERROR);
				};
			}
		}
	} while (status >= 0);
	status = -1 - status;

	log_debug2("%s: %s: returned %d, found %d", a->name, s, status, found);
	cmd_free(cmd);
	xfree(s);
	xfree(lbuf);

	status = data->ret == status;
	if (data->ret != -1 && data->re.str != NULL)
		child_exit((found && status) ? MATCH_TRUE : MATCH_FALSE);
	else if (data->ret != -1 && data->re.str == NULL)
		child_exit(status ? MATCH_TRUE : MATCH_FALSE);
	else if (data->ret == -1 && data->re.str != NULL)
		child_exit(found ? MATCH_TRUE : MATCH_FALSE);
	return (MATCH_ERROR);
}
