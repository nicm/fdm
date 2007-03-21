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

#include <unistd.h>

#include "fdm.h"

void	child_sighandler(int);

void
child_sighandler(int sig)
{
	switch (sig) {
	case SIGTERM:
		cleanup_purge();
		_exit(1);
	}
}

int
child_fork(void)
{
	pid_t		 pid;
	struct sigaction act;

	switch (pid = fork()) {
	case -1:
		fatal("fork");
	case 0:
		cleanup_flush();

		sigemptyset(&act.sa_mask);
		sigaddset(&act.sa_mask, SIGINT);
		sigaddset(&act.sa_mask, SIGTERM);
		act.sa_flags = SA_RESTART;

		act.sa_handler = SIG_IGN;
		if (sigaction(SIGINT, &act, NULL) < 0)
			fatal("sigaction");

		act.sa_handler = child_sighandler;
		if (sigaction(SIGTERM, &act, NULL) < 0)
			fatal("sigaction");

		return (0);
	default:
		return (pid);
	}
}

__dead void
child_exit(int status)
{
	cleanup_check();
	_exit(status);
}

struct child *
child_start(struct children *children, uid_t uid, int (*start)(struct child *,
    struct io *), int (*msg)(struct child *, struct msg *, struct msgbuf *),
    void *data)
{
	struct child	*child, *childp;
	int		 fds[2], n;
	u_int		 i;
	struct io	*io;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, fds) != 0)
		fatal("socketpair");

	child = xcalloc(1, sizeof *child);
	child->io = io_create(fds[0], NULL, IO_CRLF, INFTIM);
	child->data = data;
	child->msg = msg;

	if ((child->pid = child_fork()) == 0) {
		for (i = 0; i < ARRAY_LENGTH(children); i++) {
			childp = ARRAY_ITEM(children, i, struct child *);
			io_close(childp->io);
			io_free(childp->io);
			xfree(childp);
		}
		io_close(child->io);
		io_free(child->io);

		if (geteuid() == 0) {
			if (dropto(uid) != 0)
				fatal("dropto");
		}

		io = io_create(fds[1], NULL, IO_LF, INFTIM);
		n = start(child, io);
#ifdef PROFILE
		/*
		 * We want to use _exit rather than exit in the child process,
		 * and it doesn't run atexit handlers, so run _mcleanup
		 * manually to force the profiler to dump its statistics.
		 *
		 * This is icky but it works, and is only for profiling.
		 */
		extern void _mcleanup(void);
		_mcleanup();
#endif
		child_exit(n);
	}
	close(fds[1]);

	ARRAY_ADD(children, child, struct child *);
	return (child);
}


