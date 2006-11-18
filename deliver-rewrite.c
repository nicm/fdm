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

#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	rewrite_deliver(struct account *, struct action *, struct mail *);

struct deliver deliver_rewrite = { "rewrite", 1, rewrite_deliver };

int
rewrite_deliver(struct account *a, struct action *t, struct mail *m)
{
        char		*cmd, *lbuf, *line, *cause;
	size_t		 llen, len;
	struct mail	 m2;
	int	 	 in[2], out[2], error, status, res = DELIVER_FAILURE;
	struct io	*io;
	pid_t	 	 pid;

	cmd = replaceinfo(t->data, a, t);
        if (cmd == NULL || *cmd == '\0') {
		log_warnx("%s: empty command", a->name);
		if (cmd != NULL)
			xfree(cmd);
                return (DELIVER_FAILURE);
        }

	log_debug("%s: rewriting using %s", a->name, cmd);

	memset(&m2, 0, sizeof m2);
	m2.space = IO_BLOCKSIZE;
	m2.base = m2.data = xmalloc(m2.space);
	m2.size = 0;
	m2.body = -1;

	if (pipe(in) != 0)	/* child's stdin */
		fatal("pipe");
	if (pipe(out) != 0)	/* child's stdout and stderr */
		fatal("pipe");

	switch (pid = fork()) {
	case -1:
		fatal("fork");
	case 0:
		/* child */
		close(in[1]);
		close(out[0]);

		if (dup2(in[0], STDIN_FILENO) == -1) {
			log_warn("%s: %s: dup2(stdin)", a->name, cmd);
			_exit(1);
		}
		if (dup2(out[1], STDOUT_FILENO) == -1) {
			log_warn("%s: %s: dup2(stdout)", a->name, cmd);
			_exit(1);
		}
		if (dup2(out[1], STDERR_FILENO) == -1) {
			log_warn("%s: %s: dup2(stderr)", a->name, cmd);
			_exit(1);
		}

		execl(_PATH_BSHELL, "sh", "-c", cmd, (char *) NULL);
		_exit(1);
	}

	/* parent */
	close(in[0]);
	close(out[1]);

	llen = IO_LINESIZE;
	lbuf = xmalloc(llen);

	io = io_create(out[0], NULL, IO_LF);

	if (write(in[1], m->data, m->size) == -1) {
 		log_warn("%s: %s: write", a->name, cmd);
		close(out[0]);
		close(in[1]);
		goto out;
	}
	close(in[1]);

	for (;;) {
		if ((error = io_poll(io, &cause)) != 1) {
			/* normal close (error == 0) is fine */
			if (error == 0)
				break;
			log_warnx("%s: %s: %s", a->name, cmd, cause);
			free_mail(&m2);
			close(out[0]);
			goto out;
		}

		for (;;) {
			line = io_readline2(io, &lbuf, &llen);
			if (line == NULL)
				break;

			len = strlen(line);
			if (len == 0 && m2.body == -1)
				m2.body = m2.size + 1;

			resize_mail(&m2, m2.size + len + 1);

			if (len > 0)
				memcpy(m2.data + m2.size, line, len);
			/* append an LF */
			m2.data[m2.size + len] = '\n';
			m2.size += len + 1;
		}
	}

	close(out[0]);

	if (waitpid(pid, &status, 0) == -1)
		fatal("waitpid");
	if (!WIFEXITED(status)) {
		log_warnx("%s: %s: didn't exit normally", a->name, cmd);
		goto out;
	}
	error = WEXITSTATUS(status);
	if (error != 0) {
		log_warnx("%s: %s: failed, exit code %d", a->name, cmd, error);
		goto out;
	}

	if (m2.size == 0) {
		log_warnx("%s: %s: empty mail returned", a->name, cmd);
		free_mail(&m2);
		goto out;
	}

	/* replace the old mail */
	free_mail(m);
	memcpy(m, &m2, sizeof *m);

	res = DELIVER_SUCCESS;

out:
	xfree(lbuf);

	io_free(io);

	xfree(cmd);
	return (res);
}
