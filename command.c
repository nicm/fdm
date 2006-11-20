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

struct cmd *
cmd_start(const char *s, int in, int out, char *buf, size_t len, char **cause)
{
	struct cmd	*cmd;
	int	 	 fd_in[2], fd_out[2], fd_err[2];

	cmd = xmalloc(sizeof *cmd);
	cmd->pid = -1;

	fd_in[0] = fd_in[1] = -1;
	fd_out[0] = fd_out[1] = -1;
	fd_err[0] = fd_err[1] = -1;

	/* open child's stdin */
	if (in) {
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

	/* open child's stdout */
	if (out) {
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

	/* open child's stderr */
	if (pipe(fd_err) != 0) {		
		xasprintf(cause, "pipe: %s", strerror(errno));
		goto error;
	}

	/* fork the child */
	switch (cmd->pid = fork()) {
	case -1:
		xasprintf(cause, "fork: %s", strerror(errno));
		goto error;
	case 0:
		/* child */
		if (fd_in[1] != -1)
			close(fd_in[1]);
		if (fd_out[0] != -1)
			close(fd_out[0]);
		close(fd_err[0]);
		
		if (dup2(fd_in[0], STDIN_FILENO) == -1)
			fatal("dup2(stdin)");
		if (dup2(fd_out[1], STDOUT_FILENO) == -1)
			fatal("dup2(stdout)");
		if (dup2(fd_err[1], STDERR_FILENO) == -1)
			fatal("dup2(stderr)");
		
		execl(_PATH_BSHELL, "sh", "-c", s, (char *) NULL);
		fatal("execl");
	}

	/* parent */
	close(fd_in[0]);
	fd_in[0] = -1;
	close(fd_out[1]);
	fd_out[1] = -1;
	close(fd_err[1]);
	fd_err[1] = -1;

	/* write the data */
	if (fd_in[1] != -1 && buf != NULL && len > 0) {
		if (write(fd_in[1], buf, len) == -1) {
			xasprintf(cause, "write: %s", strerror(errno));
			goto error;
		}
		close(fd_in[1]);
		fd_in[1] = -1;
	}

	/* create ios */
	if (fd_out[0] != -1)
		cmd->io_out = io_create(fd_out[0], NULL, IO_LF);
	else
		cmd->io_out = NULL;
	cmd->io_err = io_create(fd_err[0], NULL, IO_LF);

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

int
cmd_poll(struct cmd *cmd, char **out, char **err, char **cause)
{
	struct io	*io, *ios[2];
	int		 status, res;

restart:
	*out = *err = NULL;
	if (cmd->io_out != NULL)
		*out = io_readline(cmd->io_out);
	if (cmd->io_err != NULL)
		*err = io_readline(cmd->io_err);
	if (*out != NULL || *err != NULL)
		return (0);

	if (cmd->io_err != NULL || cmd->io_out != NULL) {
		ios[0] = cmd->io_err;
		ios[1] = cmd->io_out;
		switch (io_polln(ios, 2, &io, cause)) {
		case -1:
			return (1);
		case 0:
			if (io == cmd->io_err)
				cmd->io_err = NULL;
			else if (io == cmd->io_out)
				cmd->io_out = NULL;
			io_close(io);
			io_free(io);
			return (0);
		}
	}

	if (cmd->io_out != NULL && IO_RDSIZE(cmd->io_out) > 0)
		goto restart;
	if (cmd->io_err != NULL && IO_RDSIZE(cmd->io_err) > 0)
		goto restart;

	res = waitpid(cmd->pid, &status, WNOHANG);
	if (res == 0 || (res == -1 && errno == ECHILD))
		return (0);
	if (res == -1) {
		xasprintf(cause, "waitpid: %s", strerror(errno));
		return (1);
	}
	if (WIFSIGNALED(status)) {	
		xasprintf(cause, "child got signal: %d", WTERMSIG(status));
		return (1);	
	}
	if (!WIFEXITED(status)) {
		xasprintf(cause, "child didn't exit normally");
		return (1);
	}
	status = WEXITSTATUS(status);
	return (-1 - status);
}

void
cmd_free(struct cmd *cmd)
{
	if (cmd->pid != -1)
		kill(cmd->pid, SIGTERM);

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
