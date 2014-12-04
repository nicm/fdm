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
#include "deliver.h"

int	 deliver_write_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_write_desc(struct actitem *, char *, size_t);

struct deliver deliver_write = {
	"write",
	DELIVER_ASUSER,
	deliver_write_deliver,
	deliver_write_desc
};

int
deliver_write_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_write_data	*data = ti->data;
	char				*path;
	FILE				*f;

	path = replacepath(&data->path, m->tags, m, &m->rml, dctx->udata->home);
	if (path == NULL || *path == '\0') {
		if (path != NULL)
			xfree(path);
		log_warnx("%s: empty command", a->name);
		return (DELIVER_FAILURE);
	}

	if (data->append) {
		log_debug2("%s: appending to %s", a->name, path);
		f = fopen(path, "a");
	} else {
		log_debug2("%s: writing to %s", a->name, path);
		f = fopen(path, "w");
	}
	if (f == NULL) {
		log_warn("%s: %s: fopen", a->name, path);
		goto error;
	}
	if (fwrite(m->data, m->size, 1, f) != 1) {
		log_warn("%s: %s: fwrite", a->name, path);
		goto error;
	}
	if (fflush(f) != 0) {
		log_warn("%s: %s: fflush", a->name, path);
		goto error;
	}
	if (fsync(fileno(f)) != 0) {
		log_warn("%s: %s: fsync", a->name, path);
		goto error;
	}
	fclose(f);

	xfree(path);
	return (DELIVER_SUCCESS);

error:
	xfree(path);
	return (DELIVER_FAILURE);
}


void
deliver_write_desc(struct actitem *ti, char *buf, size_t len)
{
	struct deliver_write_data	*data = ti->data;

	if (data->append)
		xsnprintf(buf, len, "append \"%s\"", data->path.str);
	else
		xsnprintf(buf, len, "write \"%s\"", data->path.str);
}
