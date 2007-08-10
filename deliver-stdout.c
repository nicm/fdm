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

#include <stdio.h>
#include <string.h>

#include "fdm.h"
#include "deliver.h"

int	 deliver_stdout_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_stdout_desc(struct actitem *, char *, size_t);

struct deliver deliver_stdout = {
	"stdout",
	DELIVER_INCHILD,
	deliver_stdout_deliver,
	deliver_stdout_desc
};

int
deliver_stdout_deliver(struct deliver_ctx *dctx, unused struct actitem *ti)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;

	log_debug2("%s: writing to stdout", a->name);

	if (fwrite(m->data, m->size, 1, stdout) != 1) {
		log_warn("%s: fwrite", a->name);
		return (DELIVER_FAILURE);
	}

	fflush(stdout);
	return (DELIVER_SUCCESS);
}

void
deliver_stdout_desc(unused struct actitem *ti, char *buf, size_t len)
{
	strlcpy(buf, "stdout", len);
}
