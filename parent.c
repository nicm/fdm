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

void	parent_get(struct mail *, struct msg *, void *, struct deliver_ctx *,
	    struct match_ctx *);
void	parent_done(struct io *, struct mail *, struct msg *, int);
int	parent_child(struct account *, struct mail *, const char *, uid_t,
  	    int (*)(pid_t, struct account *, struct msg *, void *, int *), 
	    void *, int *);

struct parent_action_data {
	struct action		*action;
	struct deliver_ctx	*dctx;
	struct mail		*mail;
};

int	parent_action(struct action *, struct deliver_ctx *, uid_t);
int	parent_action_hook(int, struct account *, struct msg *, void *, int *);

struct parent_cmd_data {
	struct match_ctx	 	*mctx;
	struct match_command_data	*data;
	struct mail			*mail;
};

int	parent_cmd(struct match_ctx *, struct match_command_data *, uid_t);
int	parent_cmd_hook(int, struct account *, struct msg *, void *, int *);

void
parent_get(struct mail *m, struct msg *msg, void *buf, struct deliver_ctx *dctx,
    struct match_ctx *mctx)
{
	mail_receive(m, msg);
	m->tags = buf;

	if (dctx != NULL) {
		memset(dctx, 0, sizeof dctx);
		dctx->account = msg->data.account;
		dctx->mail = m;
		dctx->decision = NULL;	/* only altered in child */
		dctx->pm_valid = &msg->data.pm_valid;
		memcpy(&dctx->pm, &msg->data.pm, sizeof dctx->pm);
	}

	if (mctx != NULL) { 
		memset(mctx, 0, sizeof mctx);
		mctx->account = msg->data.account;
		mctx->mail = m;
		mctx->decision = NULL;	/* only altered in child */
		mctx->pm_valid = msg->data.pm_valid;
		memcpy(&mctx->pm, &msg->data.pm, sizeof mctx->pm);
	}
}

void
parent_done(struct io *io, struct mail *m, struct msg *msg, int error)
{
	memset(msg, 0, sizeof msg);

	msg->type = MSG_DONE;
	msg->data.error = error;

	mail_send(m, msg);

	if (privsep_send(io, msg, m->tags, STRB_SIZE(m->tags)) != 0)
		fatalx("parent: privsep_send error");
	
	mail_close(m);
}

int
parent_child(struct account *a, struct mail *m, const char *name, uid_t uid,
    int (*hook)(pid_t, struct account *, struct msg *, void *, int *), 
    void *hookdata, int *result)
{
	struct io	*io;
	struct msg 	 msg;
	int		 status, error = 0, fds[2];
	pid_t		 pid;
	void		*buf;
	size_t		 len;
	
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
		*result = msg.data.error;

		if (buf == NULL || len == 0)
			fatalx("parent2: bad tags");
		strb_destroy(&m->tags);
		m->tags = buf;

		/* call the hook */
		if (hook(pid, a, &msg, hookdata, result) != 0)
			error = 1;

		/* free the io */
		io_close(io);
		io_free(io);

		if (waitpid(pid, &status, 0) == -1)
			fatal("waitpid");
		if (WIFSIGNALED(status)) {
			log_warnx("%s: child got signal: %d", a->name,
			    WTERMSIG(status));
			return (1);
		}
		if (!WIFEXITED(status)) {
			log_warnx("%s: child didn't exit normally", a->name);
			return (1);
		}
		status = WEXITSTATUS(status);
		if (status != 0) {
			log_warnx("%s: child returned %d", a->name, status);
			return (1);
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
	if (geteuid() == 0) {
		if (dropto(uid) != 0) {
			log_warnx("%s: can't drop privileges", a->name);
			child_exit(1);
		}
	} else {
		log_debug("%s: not root. using current user", a->name);
		uid = geteuid();
	}
#ifndef NO_SETPROCTITLE
	setproctitle("%s[%lu]", name, (u_long) uid);
#endif

	/* refresh user and home and fix tags */
	fill_info(NULL);
	update_tags(&m->tags);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* call the hook */
	if (hook(pid, a, &msg, hookdata, result) != 0)
		error = 1;

	/* inform parent we're done */
	msg.type = MSG_DONE;
	msg.data.error = *result;
	if (privsep_send(io, &msg, m->tags, STRB_SIZE(m->tags)) != 0)
		fatalx("deliver: privsep_send error");

	/* free the io */
	io_close(io);
	io_free(io);

#ifdef DEBUG
	COUNTFDS(a->name);
	xmalloc_report(a->name);
#endif

	child_exit(error);
	fatalx("child_exit: failed");
}

int
do_parent(struct child *child)
{
	struct msg	 	 msg;
	struct deliver_ctx	 dctx;
	struct match_ctx	 mctx;
	struct mail		 m;
	int			 error;
	void			*buf;
	size_t			 len;

	memset(&m, 0, sizeof m);

	if (privsep_recv(child->io, &msg, &buf, &len) != 0)
		fatalx("parent: privsep_recv error");
	log_debug2("parent: got message type %d from child %ld (%s)", msg.type,
	    (long) child->pid, child->account->name);

	switch (msg.type) {
	case MSG_ACTION:
		if (buf == NULL || len == 0)
			fatalx("parent: bad tags");
		parent_get(&m, &msg, buf, &dctx, NULL);
		error = parent_action(msg.data.action, &dctx, msg.data.uid);
		parent_done(child->io, &m, &msg, error);
		break;
	case MSG_COMMAND:
		if (buf == NULL || len == 0)
			fatalx("parent: bad tags");
		parent_get(&m, &msg, buf, NULL, &mctx);
		error = parent_cmd(&mctx, msg.data.cmddata, msg.data.uid);
		parent_done(child->io, &m, &msg, error);
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
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail; 
	struct mail			*md = &dctx->wr_mail;
	struct parent_action_data	 ad;
	int				 result;

	ad.action = t;
	ad.dctx = dctx;
	ad.mail = m;

	memset(md, 0, sizeof *md);
	/*
	 * If writing back, open a new mail now and set its ownership so it
	 *  can be accessed by the child.
	 */
	if (t->deliver->type == DELIVER_WRBACK) {
		mail_open(md, IO_BLOCKSIZE);
		if (geteuid() == 0 &&
		    fchown(md->shm.fd, conf.child_uid, conf.child_gid) != 0)
			fatal("fchown");
	}
	
	if (parent_child(a,
	    m, "deliver", uid, parent_action_hook, &ad, &result) != 0)
		return (DELIVER_FAILURE);
	return (result);
}

int
parent_action_hook(pid_t pid, struct account *a, struct msg *msg,
    void *hookdata, int *result)
{
	struct parent_action_data	*ad = hookdata;
	struct action			*t = ad->action;
	struct deliver_ctx		*dctx = ad->dctx;
	struct mail			*m = ad->mail;
	struct mail			*md = &dctx->wr_mail;

	/* check if this is the parent */
	if (pid != 0) { 
		/* use new mail if necessary */
		if (t->deliver->type != DELIVER_WRBACK)
			return (0);
		
		if (*result != DELIVER_SUCCESS) {
			mail_destroy(md);
			return (0);
		}
		
		mail_close(md);
		mail_receive(m, msg);
		log_debug2("%s: got new mail from delivery: size %zu, body %zd",
		    a->name, m->size, m->body);

		return (0);
	}

	/* this is the child. do the delivery */
	*result = t->deliver->deliver(dctx, t);
	if (t->deliver->type != DELIVER_WRBACK || *result != DELIVER_SUCCESS)
		return (0);

	mail_send(md, msg);
	log_debug2("%s: using new mail, size %zu", a->name, md->size);

	return (0);
}

int
parent_cmd(struct match_ctx *mctx, struct match_command_data *data,
    uid_t uid)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct parent_cmd_data	 cd;
	int			 result;

	cd.mctx = mctx;
	cd.data = data;

	if (parent_child(a,
	    m, "command", uid, parent_cmd_hook, &cd, &result) != 0)
		return (MATCH_ERROR);
	return (result);
}

int
parent_cmd_hook(pid_t pid, struct account *a, unused struct msg *msg, 
    void *hookdata, int *result)
{
	struct parent_cmd_data		*cd = hookdata;
	struct match_ctx		*mctx = cd->mctx;
	struct mail			*m = mctx->mail;
	struct match_command_data	*data = cd->data;
	int				 flags, status, found = 0;
	char				*s, *cause, *lbuf, *out, *err, tag[24];
	size_t				 llen;
	struct cmd		 	*cmd = NULL;
	regmatch_t			 pm[NPMATCH];
	u_int				 i;

	/* if this is the parent, do nothing */
	if (pid != 0)
		return (0);

	/* sort out the command */
	s = replace(data->cmd, m->tags, m, mctx->pm_valid, mctx->pm);
        if (s == NULL || *s == '\0') {
		log_warnx("%s: empty command", a->name);
		goto error;
        }

	log_debug2("%s: %s: started (ret=%d re=%s)", a->name, 
	    s, data->ret, data->re.str == NULL ? "none" : data->re.str);
	flags = CMD_ONCE;
	if (data->pipe)
		flags |= CMD_IN;
	if (data->re.str != NULL)
		flags |= CMD_OUT;
	cmd = cmd_start(s, flags, m->data, m->size, &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		goto error;
	}

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	do {
		status = cmd_poll(cmd, &out, &err, &lbuf, &llen, &cause);
		if (status > 0) {
			log_warnx("%s: %s: %s", a->name, s, cause);
			goto error;
		}
       		if (status < 0)
			break;
		if (err != NULL)
			log_warnx("%s: %s: %s", a->name, s, err);
		if (out == NULL || found)
			continue;
		log_debug3("%s: %s: out: %s", a->name, s, out);
			
		found = re_execute(&data->re, out, NPMATCH, pm, 0, &cause);
		if (found == -1) {
			log_warnx("%s: %s", a->name, cause);
			goto error;
		}
		if (found != 1)
			continue;
		/* save the pmatch */
		for (i = 0; i < NPMATCH; i++) {
			if (pm[i].rm_so >= pm[i].rm_eo)
				continue;
			xsnprintf(tag, sizeof tag, "command%u", i);
			add_tag(&m->tags, tag, "%.*s", (int) (pm[i].rm_eo -
			    pm[i].rm_so), out + pm[i].rm_so);
		}
	} while (status >= 0);
	status = -1 - status;

	log_debug2("%s: %s: returned %d, found %d", a->name, s, status, found);

	cmd_free(cmd);
	xfree(s);
	xfree(lbuf);

	status = data->ret == status;
	if (data->ret != -1 && data->re.str != NULL)
		*result = (found && status) ? MATCH_TRUE : MATCH_FALSE;
	else if (data->ret != -1 && data->re.str == NULL)
		*result = status ? MATCH_TRUE : MATCH_FALSE;
	else if (data->ret == -1 && data->re.str != NULL)
		*result = found ? MATCH_TRUE : MATCH_FALSE;
	else
		*result = MATCH_ERROR;

	return (0);

error:
	if (cause != NULL)
		xfree(cause);
	if (cmd != NULL)
		cmd_free(cmd);
	if (s != NULL)
		xfree(s);
	if (lbuf != NULL)
		xfree(lbuf);

	return (1);
}
