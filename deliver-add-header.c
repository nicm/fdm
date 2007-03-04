/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <string.h>

#include "fdm.h"

int	 add_header_deliver(struct deliver_ctx *, struct action *);
void	 add_header_desc(struct action *, char *, size_t);

struct deliver deliver_add_header = { DELIVER_INCHILD,
				      add_header_deliver,
				      add_header_desc };

int
add_header_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct account		*a = dctx->account;
	struct mail		*m = dctx->mail;
	struct add_header_data	*data = t->data;
	char			*value;
	
	value = replace(data->value, m->tags, m, *dctx->pm_valid, dctx->pm);
	if (value == NULL)
		return (DELIVER_SUCCESS);
	
	if (insert_header(m, NULL, "%s: %s", data->hdr, value) != 0) {
		log_warnx("%s: failed to add header %s (%s)", a->name,
		    data->hdr, value);
		return (DELIVER_FAILURE);
	}
	
	xfree(value);

	ARRAY_FREE(&m->wrapped);
	fill_wrapped(m);

	*dctx->pm_valid = 0;
	
	return (DELIVER_SUCCESS);
}

void
add_header_desc(struct action *t, char *buf, size_t len)
{
	struct add_header_data	*data = t->data;

	xsnprintf(buf, len, "add-header \"%s\" \"%s\"", data->hdr, data->value);
}
