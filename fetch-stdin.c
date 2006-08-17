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
 
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

int	stdin_connect(struct account *);
int	stdin_disconnect(struct account *);
int	stdin_fetch(struct account *, struct mail *);

struct fetch	fetch_stdin = { "stdin", "stdin",
			       stdin_connect, 
			       NULL,
			       stdin_fetch, 
			       stdin_disconnect };

int
stdin_connect(struct account *a)
{
	struct stdin_data	*data;

	if (isatty(STDIN_FILENO)) {
		log_warnx("%s: stdin is a tty. ignoring", a->name);
		return (1);
	}

	data = a->data;

	data->io = io_create(STDIN_FILENO, NULL, IO_LF);
	if (conf.debug > 3)
		data->io->dup_fd = STDOUT_FILENO;

	return (0);
}

int
stdin_disconnect(struct account *a)
{
	struct stdin_data	*data;

	data = a->data;

	io_free(data->io);

	close(STDIN_FILENO);

	return (0);
}

int
stdin_fetch(struct account *a, struct mail *m)
{
	struct stdin_data	*data;
	int		 	 error, done;
	char			*line;
	size_t			 len;

	data = a->data;

	if (m->data == NULL) {
		m->space = 4096;
		m->base = m->data = malloc(m->space);
		m->size = 0;
		m->body = -1;
	}

	done = 0;
	for (;;) {
		if ((error = io_poll(data->io)) != 1) {
			/* normal close (error == 0) is fine */
			if (error == 0)
				break;
			return (1);
		}

		for (;;) {
			line = io_readline(data->io);
			if (line == NULL)
				break;

			len = strlen(line);
			if (len == 0 && m->body == -1)
				m->body = m->size + 1;
			
			ENSURE_SIZE(m->data, m->space, m->size + len + 1);
			m->base = m->data;

			if (len > 0)
				memcpy(m->data + m->size, line, len);
			/* append an LF */
			m->data[m->size + len] = '\n';
			m->size += len + 1;
		}
		if (done)
			break;
	}

	trim_from(m);
	return (0);
}
