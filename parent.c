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
#include <sys/wait.h>

#include <unistd.h>

#include "fdm.h"

int	perform_actions(struct account *, struct mail *, struct rule *);
int	deliverfork(uid_t, struct account *, struct mail *, struct action *);

int
parent(int fd, pid_t pid)
{
	struct io	*io;
	struct msg	 msg;
	int		 status, error;

	io = io_create(fd, NULL, IO_LF);
	log_debug("parent: started, pid %ld", (long) getpid());

#ifndef NO_SETPROCTITLE
	setproctitle("parent");
#endif

	do {
		if (io_wait(io, sizeof msg, NULL) != 0) 
			fatalx("parent: io_wait error");
		if (io_read2(io, &msg, sizeof msg) != 0)
			fatalx("parent: io_read2 error");
		log_debug2("parent: got message type %d from child", msg.type);

		switch (msg.type) {
		case MSG_DELIVER:
			if (io_wait(io, msg.mail.size, NULL) != 0) 
				fatalx("parent: io_wait error"); 
			msg.mail.base = io_read(io, msg.mail.size);
			if (msg.mail.base == NULL)
				fatalx("parent: io_read error"); 
			msg.mail.data = msg.mail.base;

			trim_from(&msg.mail);
			error = perform_actions(msg.acct, &msg.mail, msg.rule);
			free_mail(&msg.mail);

			msg.type = MSG_DONE;
			msg.error = error;
			io_write(io, &msg, sizeof msg);
			if (io_flush(io, NULL) != 0)
				fatalx("parent: io_flush error");
			break;
		case MSG_DONE:
			fatalx("parent: unexpected message");
		case MSG_EXIT:
			break;
		}

	} while (msg.type != MSG_EXIT);

	io_free(io);

#ifdef DEBUG
	xmalloc_dump("parent");
#endif 

	if (waitpid(pid, &status, 0) == -1)
		fatal("waitpid");
	if (!WIFEXITED(status))
		return (1);
	return (WEXITSTATUS(status));
}

int
perform_actions(struct account *a, struct mail *m, struct rule *r)
{
	struct action	*t;
	u_int		 i, j;
	int		 find;
	struct users	*users;
	uid_t		 uid;
	
	for (i = 0; i < ARRAY_LENGTH(r->actions); i++) {
		t = ARRAY_ITEM(r->actions, i, struct action *);
		if (t->deliver->deliver == NULL)
			continue;
		log_debug2("%s: action %s", a->name, t->name);

		if (geteuid() != 0) {
			log_debug2("%s: not root. using current user", a->name);
			/* do the delivery without forking */
			if (t->deliver->deliver(a, t, m) != DELIVER_SUCCESS)
				return (1);
			continue;
		}
	
		/* figure out the users to use. it would be nice to call
		   find_users as non-root :-( */
		users = NULL;
		if (r->find_uid) {		/* rule comes first */
			find = 1;
			users = find_users(m);
		} else if (r->users != NULL) {
			find = 0;
			users = r->users;
		} else if (t->find_uid) {
			find = 1;
			users = find_users(m);
		} else if (t->users != NULL) {	/* then action */
			find = 0;
			users = t->users;
		}
		if (users == NULL) {
			find = 1;
			users = xmalloc(sizeof *users);
			ARRAY_INIT(users);
			ARRAY_ADD(users, conf.def_user, uid_t);
		}

		for (j = 0; j < ARRAY_LENGTH(users); j++) {
			/* fork and deliver */
			uid = ARRAY_ITEM(users, j, uid_t);
			if (deliverfork(uid, a, m, t) != DELIVER_SUCCESS) {
				if (find)
					xfree(users);
				return (1);
			}
		}

		if (find)
			xfree(users);
	}

	return (0);
}

int
deliverfork(uid_t uid, struct account *a, struct mail *m, struct action *t)
{
	int	status;
	pid_t	pid;

	pid = fork();
	if (pid == -1) {
		log_warn("%s: fork", a->name);
		return (DELIVER_FAILURE);
	}
	if (pid != 0) {
		/* parent process. wait for child */
		log_debug2("%s: forked. child pid is %ld", a->name, (long) pid);
		if (waitpid(pid, &status, 0) == -1)
			fatal("waitpid");
		if (!WIFEXITED(status)) {
			log_warnx("%s: child didn't exit normally", a->name);
			return (DELIVER_FAILURE);
		}
		return (WEXITSTATUS(status));
	}
		
	/* child process. change user and group */
	log_debug("%s: delivering using user %lu", a->name, (u_long) uid);
	if (dropto(uid, NULL) != 0) {
		log_warnx("%s: can't drop privileges", a->name);
		_exit(DELIVER_FAILURE);
	}
#ifndef NO_SETPROCTITLE
	setproctitle("deliver[%lu]", (u_long) uid);
#endif

	/* refresh user and home */
	fill_info(NULL);	
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* do the delivery */
	_exit(t->deliver->deliver(a, t, m));
	return (DELIVER_FAILURE); /* yuk */
}
