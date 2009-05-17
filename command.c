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

#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

#define CMD_DEBUG(io, fmt, ...)
#ifndef CMD_DEBUG
#define CMD_DEBUG(cmt, fmt, ...) \
	log_debug3("%s: (%d) " fmt, __func__, cmd->pid, ## __VA_ARGS__)
#endif

/* Start a command. */
struct cmd *
cmd_start(const char *s, int flags, const char *buf, size_t len, char **cause)
{
	struct cmd	*cmd;
	int	 	 fd_in[2], fd_out[2], fd_err[2];

	cmd = xmalloc(sizeof *cmd);
	cmd->pid = -1;
	cmd->flags = flags;

	if (buf != NULL && len != 0 && flags & CMD_IN) {
		cmd->buf = buf;
		cmd->len = len;
	} else {
		cmd->buf = NULL;
		cmd->len = 0;
	}

	fd_in[0] = fd_in[1] = -1;
	fd_out[0] = fd_out[1] = -1;
	fd_err[0] = fd_err[1] = -1;

	/* Open child's stdin. */
	if (flags & CMD_IN) {
		if (pipe(fd_in) != 0) {
			xasprintf(cause, "pipe: %s", strerror(errno));
			goto error;
		}
	} else {
		fd_in[0] = open(_PATH_DEVNULL, O_RDONLY, 0);
		if (fd_in[0] < 0) {
			xasprintf(cause, "open: %s", strerror(errno));
			goto error;
		}
	}

	/* Open child's stdout. */
	if (flags & CMD_OUT) {
		if (pipe(fd_out) != 0) {
			xasprintf(cause, "pipe: %s", strerror(errno));
			goto error;
		}
	} else {
		fd_out[1] = open(_PATH_DEVNULL, O_WRONLY, 0);
		if (fd_out[1] < 0) {
			xasprintf(cause, "open: %s", strerror(errno));
			goto error;
		}
	}

	/* Open child's stderr. */
	if (pipe(fd_err) != 0) {
		xasprintf(cause, "pipe: %s", strerror(errno));
		goto error;
	}

	/* Fork the child. */
	switch (cmd->pid = fork()) {
	case -1:
		xasprintf(cause, "fork: %s", strerror(errno));
		goto error;
	case 0:
		/* Child. */
		cmd->pid = getpid();
		CMD_DEBUG(cmd, "started (child)");

		if (fd_in[1] != -1)
			close(fd_in[1]);
		if (fd_out[0] != -1)
			close(fd_out[0]);
		close(fd_err[0]);

		if (dup2(fd_in[0], STDIN_FILENO) == -1)
			fatal("dup2(stdin) failed");
		close(fd_in[0]);
		if (dup2(fd_out[1], STDOUT_FILENO) == -1)
			fatal("dup2(stdout) failed");
		close(fd_out[1]);
		if (dup2(fd_err[1], STDERR_FILENO) == -1)
			fatal("dup2(stderr) failed");
		close(fd_err[1]);

#ifdef SIGINFO
                if (signal(SIGINFO, SIG_DFL) == SIG_ERR)
			fatal("signal failed");
#endif
                if (signal(SIGUSR1, SIG_DFL) == SIG_ERR)
			fatal("signal failed");
                if (signal(SIGINT, SIG_DFL) == SIG_ERR)
			fatal("signal failed");
                if (signal(SIGTERM, SIG_DFL) == SIG_ERR)
			fatal("signal failed");
                if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
			fatal("signal failed");
                if (signal(SIGUSR1, SIG_DFL) == SIG_ERR)
			fatal("signal failed");
                if (signal(SIGUSR2, SIG_DFL) == SIG_ERR)
			fatal("signal failed");

		execl(_PATH_BSHELL, "sh", "-c", s, (char *) NULL);
		fatal("execl failed");
	}
	CMD_DEBUG(cmd, "started (parent)");

	/* XXX Check if the child has actually started. */
	if (kill(cmd->pid, 0) != 0) {
		if (errno == ESRCH)
			CMD_DEBUG(cmd, "child not running");
		else if (errno != EPERM)
			fatal("kill");
	}

	/* Parent. */
	close(fd_in[0]);
	fd_in[0] = -1;
	close(fd_out[1]);
	fd_out[1] = -1;
	close(fd_err[1]);
	fd_err[1] = -1;

	/* Create ios. */
	cmd->io_in = NULL;
	if (fd_in[1] != -1) {
		cmd->io_in = io_create(fd_in[1], NULL, IO_LF);
		io_writeonly(cmd->io_in);
 		if (cmd->len != 0)
			cmd->io_in->flags |= IOF_MUSTWR;
	}
	cmd->io_out = NULL;
	if (fd_out[0] != -1) {
		cmd->io_out = io_create(fd_out[0], NULL, IO_LF);
		io_readonly(cmd->io_out);
	}
	cmd->io_err = io_create(fd_err[0], NULL, IO_LF);
	io_readonly(cmd->io_err);

	return (cmd);

error:
	if (cmd->pid != -1)
		kill(cmd->pid, SIGTERM);

	if (fd_in[0] != -1)
		close(fd_in[0]);
	if (fd_in[1] != -1)
		close(fd_in[1]);
	if (fd_out[0] != -1)
		close(fd_out[0]);
	if (fd_out[1] != -1)
		close(fd_out[1]);
	if (fd_err[0] != -1)
		close(fd_err[0]);
	if (fd_err[1] != -1)
		close(fd_err[1]);

	xfree(cmd);
	return (NULL);
}

/*
 * Poll a command. Returns -1 on error, 0 if output is found, or the child's
 * return code + 1 if it has exited.
 */
int
cmd_poll(struct cmd *cmd, char **out, char **err,
    char **lbuf, size_t *llen, int timeout, char **cause)
{
	struct io	*io, *ios[3];
	size_t		 len;
	ssize_t		 n;
	pid_t		 pid;
	int		 flags;

	CMD_DEBUG(cmd,
	    "in=%p, out=%p, err=%p", cmd->io_in, cmd->io_out, cmd->io_err);

	/* Reset return pointers. */
	if (err != NULL)
		*err = NULL;
	if (out != NULL)
		*out = NULL;

	/*
	 * Handle fixed buffer. We can't just write everything in cmd_start
	 * as the child may block waiting for us to read. So, write as much
	 * as possible here while still polling the others. If CMD_ONCE is set
	 * stdin is closed when the buffer is done.
	 */
	if (cmd->len != 0 && cmd->io_in != NULL && !IO_CLOSED(cmd->io_in)) {
		CMD_DEBUG(cmd, "writing, %zu left", cmd->len);
		n = write(cmd->io_in->fd, cmd->buf, cmd->len);
		CMD_DEBUG(cmd, "write returned %zd (errno=%d)", n, errno);
		switch (n) {
		case 0:
			errno = EPIPE;
			/* FALLTHROUGH */
		case -1:

			if (errno == EINTR || errno == EAGAIN)
				break;
			/*
			 * Ignore closed input, rely on child returning non-
			 * zero on error and caller checking before writing to
			 * it.
			 */
			if (errno == EPIPE) {
				cmd->len = 0;
				break;
			}
			xasprintf(cause, "write: %s", strerror(errno));
			return (-1);
		default:
			cmd->buf += n;
			cmd->len -= n;
			break;
		}
		if (cmd->len == 0) {
			if (cmd->flags & CMD_ONCE) {
				CMD_DEBUG(cmd, "write finished, closing");
				io_close(cmd->io_in);
				io_free(cmd->io_in);
				cmd->io_in = NULL;
			} else {
				CMD_DEBUG(cmd, "write finished");
				cmd->io_in->flags &= ~IOF_MUSTWR;
			}
		}
	}

	/* No lines available. If there is anything open, try and poll it. */
	if (cmd->io_in != NULL || cmd->io_out != NULL || cmd->io_err != NULL) {
		ios[0] = cmd->io_in;
		ios[1] = cmd->io_out;
		ios[2] = cmd->io_err;
		CMD_DEBUG(cmd, "polling, timeout=%d", timeout);
		switch (io_polln(ios, 3, &io, timeout, cause)) {
		case -1:
			if (errno == EAGAIN)
				break;
			return (-1);
		case 0:
			/*
			 * Check for closed. It'd be nice for closed input to
			 * be an error, but we can't tell the difference
			 * between error and normal child exit, so just free it
			 * and rely on the caller to handle it.
			 */
			if (io == cmd->io_in) {
				CMD_DEBUG(cmd, "closing in");
				io_close(cmd->io_in);
				io_free(cmd->io_in);
				cmd->io_in = NULL;
			}
			if (io == cmd->io_out && IO_RDSIZE(cmd->io_out) == 0) {
				CMD_DEBUG(cmd, "closing out");
				io_close(cmd->io_out);
				io_free(cmd->io_out);
				cmd->io_out = NULL;
			}
			if (io == cmd->io_err && IO_RDSIZE(cmd->io_err) == 0) {
				CMD_DEBUG(cmd, "closing err");
				io_close(cmd->io_err);
				io_free(cmd->io_err);
				cmd->io_err = NULL;
			}
			break;
		}
	}

	/*
	 * Retrieve and return a line if possible. This must be after the
	 * poll otherwise it'll get screwed up by external poll, like so:
	 *	- no data buffered so test for line finds nothing
	 *	- all sockets polled here, the data being waited for has
	 *	  arrived, it is read and buffered and the function returns
	 *	- the external poll blocks, but since the data being waited
	 *	  on has already arrived, doesn't wake up
	 * Maybe an EXTERNALPOLL flag to eliminate the double-poll would clear
	 * things up? Just an IO_CLOSED check here...
	 */
	if (cmd->io_err != NULL) {
		CMD_DEBUG(cmd, "err has %zu bytes", IO_RDSIZE(cmd->io_err));
		*err = io_readline2(cmd->io_err, lbuf, llen);
		if (*err != NULL) {
			/* Strip CR if the line is terminated by one. */
			len = strlen(*err);
			if (len > 0 && (*err)[len - 1] == '\r')
				(*err)[len - 1] = '\0';
			return (0);
		}
	}
	if (cmd->io_out != NULL) {
		CMD_DEBUG(cmd, "out has %zu bytes", IO_RDSIZE(cmd->io_out));
		*out = io_readline2(cmd->io_out, lbuf, llen);
		if (*out != NULL) {
			/* Strip CR if the line is terminated by one. */
			len = strlen(*out);
			if (len > 0 && (*out)[len - 1] == '\r')
				(*out)[len - 1] = '\0';
			return (0);
		}
	}

	/* If anything is still open, return now and don't check the child. */
	if (cmd->io_in != NULL || cmd->io_out != NULL || cmd->io_err != NULL)
		return (0);

	/* Everything is closed. Check the child. */
	CMD_DEBUG(cmd, "waiting for child, timeout=%d", timeout);
	flags = WNOHANG;
	if (timeout != 0) {
		flags = 0;
		timer_set(timeout / 1000);
	}
	pid = waitpid(cmd->pid, &cmd->status, flags);
	if (timeout != 0)
		timer_cancel();
	if (pid == -1) {
		if (timeout != 0 && errno == EINTR && timer_expired())
			errno = ETIMEDOUT;
		xasprintf(cause, "waitpid: %s", strerror(errno));
		return (-1);
	}
	if (pid == 0)
		return (0);

	/* Child is dead, sort out what to return. */
	CMD_DEBUG(cmd, "child exited, status=%d", cmd->status);
	cmd->pid = -1;
	if (WIFSIGNALED(cmd->status)) {
		xasprintf(cause, "child got signal: %d", WTERMSIG(cmd->status));
		return (-1);
	}
	if (!WIFEXITED(cmd->status)) {
		xasprintf(cause, "child didn't exit normally");
		return (-1);
	}
	cmd->status = WEXITSTATUS(cmd->status);
	return (1 + cmd->status);
}

void
cmd_free(struct cmd *cmd)
{
	if (cmd->pid != -1)
		kill(cmd->pid, SIGTERM);

	if (cmd->io_in != NULL) {
		io_close(cmd->io_in);
		io_free(cmd->io_in);
	}
	if (cmd->io_out != NULL) {
		io_close(cmd->io_out);
		io_free(cmd->io_out);
	}
	if (cmd->io_err != NULL) {
		io_close(cmd->io_err);
		io_free(cmd->io_err);
	}

	xfree(cmd);
}
