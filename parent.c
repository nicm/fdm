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

int	do_action(struct account *, struct action *, struct mail *, uid_t);
int	deliverfork(uid_t, struct account *, struct mail *, struct action *);

int
parent(int fd, pid_t pid)
{
	struct io	*io;
	struct msg	 msg;
	struct mail	*m;
	int		 status, error;
	void		*buf;
	size_t		 len;
	struct msgdata	*data;
	uid_t		 uid;

#ifdef DEBUG
	xmalloc_clear();
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
			if (buf == NULL || len != m->size)
				fatalx("parent: bad mail");
			m->base = buf;
			m->data = m->base;

			ARRAY_INIT(&m->tags);
			m->wrapped = NULL;

			trim_from(m);
			uid = data->uid;
			error = do_action(data->account, data->action, m, uid);
			free_mail(m);

			msg.type = MSG_DONE;
			msg.data.error = error;
			if (privsep_send(io, &msg, NULL, 0) != 0)
				fatalx("parent: privsep_send error");
			break;
		case MSG_DONE:
			fatalx("parent: unexpected message");
		case MSG_EXIT:
			if (buf != NULL || len != 0)
				fatalx("parent: invalid message");
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
do_action(struct account *a, struct action *t, struct mail *m, uid_t uid)
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
	if (uid != geteuid()) {
		if (dropto(uid) != 0) {
			log_warnx("%s: can't drop privileges", a->name);
			_exit(DELIVER_FAILURE);
		}
	} else
		log_debug("%s: user already %lu", a->name, (u_long) uid);
#ifndef NO_SETPROCTITLE
	setproctitle("deliver[%lu]", (u_long) uid);
#endif

	/* refresh user and home */
	fill_info(NULL);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	/* do the delivery */
	_exit(t->deliver->deliver(a, t, m));
	return (DELIVER_FAILURE);
}
