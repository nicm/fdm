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

int	 deliver_stdout_deliver(struct deliver_ctx *, struct action *);
void	 deliver_stdout_desc(struct action *, char *, size_t);

struct deliver deliver_stdout = {
	DELIVER_INCHILD, 
	deliver_stdout_deliver,
	deliver_stdout_desc
};

int
deliver_stdout_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_stdout_data	*data = t->data;
        char				*from;

	log_debug2("%s: writing to stdout", a->name);
	
	if (data->add_from) {
		from = make_from(m);
		log_debug3("%s: using from line: %s", a->name, from);

		if (fwrite(from, strlen(from), 1, stdout) != 1) {
			log_warn("%s: fwrite", a->name);
			return (DELIVER_FAILURE);
		}
		if (fputc('\n', stdout) == EOF) {
			log_warn("%s: fputc", a->name);
			return (DELIVER_FAILURE);
		}
	}

	if (fwrite(m->data, m->size, 1, stdout) != 1) {
		log_warn("%s: fwrite", a->name);
		return (DELIVER_FAILURE);
	}

	fflush(stdout);
	return (DELIVER_SUCCESS);
}

void
deliver_stdout_desc(struct action *t, char *buf, size_t len)
{
	struct deliver_stdout_data	*data = t->data;

	xsnprintf(buf, len, "stdout%s", data->add_from ? " add-from" : "");
}
