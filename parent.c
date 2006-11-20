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

int	do_action(struct account *, struct action *, struct mail *, uid_t);
int	do_cmd(struct account *, struct command_data *, struct mail *, uid_t);
int	deliverfork(uid_t, struct account *, struct mail *, struct action *);

int
parent(int fd, pid_t pid)
{
	struct io	*io;
	struct msg	 msg;
	struct mail	*m;
	int		 status, error;
#ifdef DEBUG
	int		 fd2;
#endif
	void		*buf;
	size_t		 len;
	struct msgdata	*data;
	uid_t		 uid;

#ifdef DEBUG
	xmalloc_clear();

	fd2 = open(_PATH_DEVNULL, O_RDONLY, 0);
	close(fd2);
	log_debug2("parent: last fd on entry %d", fd);
#endif

	io = io_create(fd, NULL, IO_LF);
	log_debug("parent: started, pid %ld", (long) getpid());

#ifndef NO_SETPROCTITLE
	setproctitle("parent");
#endif

	data = &msg.data;
	m = &data->mail;
	do {
		if (privsep_recv(io, &msg, &buf, &len) != 0)
			fatalx("parent: privsep_recv error");
		log_debug2("parent: got message type %d", msg.type);

		switch (msg.type) {
		case MSG_ACTION:
			if (buf == NULL || len != m->size || len == 0)
				fatalx("parent: bad mail");

			m->base = buf;
			m->data = m->base;

			ARRAY_INIT(&m->tags);
			m->wrapped = NULL;

			uid = data->uid;
			error = do_action(data->account, data->action, m, uid);

			msg.type = MSG_DONE;
			msg.data.error = error;

			if (data->action->deliver->type == DELIVER_WRBACK) {
				if (privsep_send(io, 
				    &msg, m->data, m->size) != 0)
					fatalx("parent: privsep_send error");
			} else {
				if (privsep_send(io, &msg, NULL, 0) != 0)
					fatalx("parent: privsep_send error");
			}

			free_mail(m);
			break;
		case MSG_COMMAND:
			if (buf == NULL || len != m->size || len == 0)
				fatalx("parent: bad mail");

			m->base = buf;
			m->data = m->base;

			ARRAY_INIT(&m->tags);
			m->wrapped = NULL;

			uid = data->uid;
			error = do_cmd(data->account, data->cmddata, m, uid);

			msg.type = MSG_DONE;
			msg.data.error = error;
			if (privsep_send(io, &msg, NULL, 0) != 0)
				fatalx("parent: privsep_send error");

			free_mail(m);
			break;
		case MSG_DONE:
			fatalx("parent: unexpected message");
		case MSG_EXIT:
			if (buf != NULL || len != 0)
				fatalx("parent: invalid message");
			break;
		}
	} while (msg.type != MSG_EXIT);

	io_close(io);
	io_free(io);

#ifdef DEBUG
	xmalloc_dump("parent");

	fd = open(_PATH_DEVNULL, O_RDONLY, 0);
	close(fd);
	log_debug2("parent: last fd on exit %d", fd);
#endif

	if (waitpid(pid, &status, 0) == -1)
		fatal("waitpid");
	if (WIFSIGNALED(status))
		return (1);
	if (!WIFEXITED(status))
		return (1);
	return (WEXITSTATUS(status));
}

int
do_action(struct account *a, struct action *t, struct mail *m, uid_t uid)
{
	int		 status;
	pid_t		 pid;
	int		 fds[2];
	struct io	*io;
	struct msg	 msg;
	struct mail	*md;
	void		*buf;
	size_t		 len;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, fds) != 0)
		fatal("socketpair");
	pid = fork();
	if (pid == -1) {
		close(fds[0]);
		close(fds[1]);
		log_warn("%s: fork", a->name);
		return (DELIVER_FAILURE);
	}
	if (pid != 0) {
		/* create privsep io */
		close(fds[1]);
		io = io_create(fds[0], NULL, IO_LF);

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

		/* reread mail if necessary */
		if (t->deliver->type == DELIVER_WRBACK) {
			md = &msg.data.mail;
			if (buf == NULL || len != md->size || len == 0)
				fatalx("parent2: bad mail");

			log_debug2("%s: got new mail from delivery, size %zu", 
			    a->name, m->size);

			free_mail(m);
			memcpy(m, md, sizeof *m);
			m->base = buf;
			m->data = m->base;
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
		return (msg.data.error);
	}

	/* create privsep io */
 	close(fds[0]);
	io = io_create(fds[1], NULL, IO_LF);

	/* child process. change user and group */
	log_debug("%s: trying to deliver using uid %lu", a->name, (u_long) uid);
	if (geteuid() == 0) {
		if (dropto(uid) != 0) {
			log_warnx("%s: can't drop privileges", a->name);
			_exit(DELIVER_FAILURE);
		}
	} else
		log_debug("%s: not root. using current user", a->name);
#ifndef NO_SETPROCTITLE
	setproctitle("deliver[%lu]", (u_long) uid);
#endif

	/* refresh user and home */
	fill_info(NULL);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* do the delivery */
	msg.data.error = t->deliver->deliver(a, t, m);

	/* inform parent we're done */
	msg.type = MSG_DONE;
	if (t->deliver->type == DELIVER_WRBACK) {
		log_debug2("%s: sending new mail to parent, size %zu", a->name,
		    m->size);
		memcpy(&msg.data.mail, m, sizeof msg.data.mail);
		if (privsep_send(io, &msg, m->data, m->size) != 0)
			fatalx("deliver: privsep_send error");
	} else {
		if (privsep_send(io, &msg, NULL, 0) != 0)
			fatalx("deliver: privsep_send error");
	}

	io_close(io);
	io_free(io);

	_exit(0);
	return (DELIVER_FAILURE);
}

int
do_cmd(struct account *a, struct command_data *data, struct mail *m, uid_t uid)
{
	int		 status, found;
	pid_t		 pid;
	char		*s, *cause, *out, *err;
	struct cmd	*cmd;

	pid = fork();
	if (pid == -1) {
		log_warn("%s: fork", a->name);
		return (MATCH_ERROR);
	}
	if (pid != 0) {
 		/* parent process. wait for child */
		log_debug2("%s: forked. child pid is %ld", a->name, (long) pid);

		if (waitpid(pid, &status, 0) == -1) {
			log_warn("%s: waitpid", a->name);
			return (MATCH_ERROR);
		}
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
			_exit(MATCH_ERROR);
		}
	} else
		log_debug("%s: not root. using current user", a->name);
#ifndef NO_SETPROCTITLE
	setproctitle("command[%lu]", (u_long) uid);
#endif

	/* refresh user and home */
	fill_info(NULL);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* sort out the command */
	s = replaceinfo(data->cmd, a, NULL);
        if (s == NULL || *s == '\0') {
		log_warnx("%s: empty command", a->name);
		_exit(MATCH_ERROR);
        }	

	log_debug2("%s: %s: started (ret=%d re=%s)", a->name, s, data->ret,
	    data->re_s == NULL ? "none" : data->re_s);
	cmd = cmd_start(s, data->pipe, data->re_s != NULL, m->data, m->size,
	    &cause);
	if (cmd == NULL) {
		log_warnx("%s: %s: %s", a->name, s, cause);
		xfree(cause);
		xfree(s);
		_exit(MATCH_ERROR);
	}

	found = 0;
	do {
		status = cmd_poll(cmd, &out, &err, &cause);
		if (status > 0) {
			log_warnx("%s: %s: %s", a->name, s, cause);
			xfree(cause);
			cmd_free(cmd);
			xfree(s);
			_exit(MATCH_ERROR);
		}
       		if (status == 0) {
			if (err != NULL) {
				log_warnx("%s: %s: %s", a->name, s, err);

				xfree(err);
			}
			if (out != NULL) {
				log_debug3("%s: %s: out: %s", a->name, s, out);

				switch (regexec(&data->re, out, 0, NULL, 0)) {
				case 0:
					found = 1;
					break;
				case REG_NOMATCH:
					break;
				default:
					log_warnx("%s: %s: %s: regexec failed", 
					    a->name, s, data->re_s);
					cmd_free(cmd);
					xfree(s);
					_exit(MATCH_ERROR);
				}

				xfree(out);
			}
		}
	} while (status >= 0);
	status = -1 - status;

	log_debug2("%s: %s: returned %d, found %d", a->name, s, status, found);
	cmd_free(cmd);
	xfree(s);

	status = data->ret == status;
	if (data->ret != -1 && data->re_s != NULL)
		_exit((found && status) ? MATCH_TRUE : MATCH_FALSE);
	else if (data->ret != -1 && data->re_s == NULL)
		_exit(status ? MATCH_TRUE : MATCH_FALSE);
	else if (data->ret == -1 && data->re_s != NULL)
		_exit(found ? MATCH_TRUE : MATCH_FALSE);
	return (MATCH_ERROR);
}
