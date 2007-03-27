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
#include "deliver.h"

int	 deliver_add_header_deliver(struct deliver_ctx *, struct action *);
void	 deliver_add_header_desc(struct action *, char *, size_t);

struct deliver deliver_add_header = {
	"add-header",
	DELIVER_INCHILD,
	deliver_add_header_deliver,
	deliver_add_header_desc
};

int
deliver_add_header_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct account			*a = dctx->account;
	struct mail			*m = dctx->mail;
	struct deliver_add_header_data	*data = t->data;
	char				*hdr, *value = NULL;

	hdr = replacestr(&data->hdr, m->tags, m, &m->rml);
	if (hdr == NULL || *hdr == '\0') {
		log_warnx("%s: empty header", a->name);
		goto error;
	}
	value = replacestr(&data->value, m->tags, m, &m->rml);
	if (value == NULL) {
		log_warnx("%s: bad value for header %s", a->name, hdr);
		goto error;
	}
	log_debug2("%s: adding header: %s", a->name, hdr);
	
	if (insert_header(m, NULL, "%s: %s", hdr, value) != 0) {
		log_warnx("%s: failed to add header %s (%s)", a->name,
		    hdr, value);
		goto error;
	}

	ARRAY_FREE(&m->wrapped);
	m->wrapchar = '\0';
	fill_wrapped(m);

	/* invalidate the match data since stuff may have moved */
	m->rml.valid = 0;

	xfree(hdr);
	xfree(value);
	return (DELIVER_SUCCESS);

error:
	if (hdr != NULL)
		xfree(hdr);
	if (value != NULL)
		xfree(value);
	return (DELIVER_FAILURE);
}

void
deliver_add_header_desc(struct action *t, char *buf, size_t len)
{
	struct deliver_add_header_data	*data = t->data;

	xsnprintf(buf, len,
	    "add-header \"%s\" \"%s\"", data->hdr.str, data->value.str);
}
