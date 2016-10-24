/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicholas.marriott@gmail.com>
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

int	 deliver_tag_deliver(struct deliver_ctx *, struct actitem *);
void	 deliver_tag_desc(struct actitem *, char *, size_t);

struct deliver deliver_tag = {
	"tag",
	DELIVER_INCHILD,
	deliver_tag_deliver,
	deliver_tag_desc
};

int
deliver_tag_deliver(struct deliver_ctx *dctx, struct actitem *ti)
{
	struct account		*a = dctx->account;
	struct mail		*m = dctx->mail;
	struct deliver_tag_data	*data = ti->data;
	char			*tk, *tv;

	tk = replacestr(&data->key, m->tags, m, &m->rml);
	if (data->value.str != NULL)
		tv = replacestr(&data->value, m->tags, m, &m->rml);
	else
		tv = xstrdup("");

	if (tk == NULL || tv == NULL) {
		if (tk != NULL)
			xfree(tk);
		if (tv != NULL)
			xfree(tv);
		return (DELIVER_SUCCESS);
	}

	if (*tk != '\0') {
		log_debug2("%s: tagging message: %s (%s)", a->name, tk, tv);
		add_tag(&m->tags, tk, "%s", tv);
	}

	xfree(tk);
	xfree(tv);

	return (DELIVER_SUCCESS);
}

void
deliver_tag_desc(struct actitem *ti, char *buf, size_t len)
{
	struct deliver_tag_data	*data = ti->data;

	if (data->value.str == NULL)
		xsnprintf(buf, len, "tag \"%s\"", data->key.str);
	else {
		xsnprintf(buf, len,
		    "tag \"%s\" value \"%s\"", data->key.str, data->value.str);
	}
}
