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
#include <vis.h>

#include "fdm.h"
#include "deliver.h"

int	 deliver_append_string_deliver(struct deliver_ctx *, struct action *);
void	 deliver_append_string_desc(struct action *, char *, size_t);

struct deliver deliver_append_string = {
	"append-string",
	DELIVER_INCHILD,
	deliver_append_string_deliver,
	deliver_append_string_desc
};

int
deliver_append_string_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct mail	*m = dctx->mail;
	char		*ptr = t->data;
	size_t		 len;
	
	len = strlen(ptr);
	resize_mail(m, m->size + len);
	memcpy(m->data + m->size, ptr, len);
	m->size += len;
	
	return (DELIVER_SUCCESS);
}

void
deliver_append_string_desc(struct action *t, char *buf, size_t len)
{
	size_t			 sz;

	*buf = '\0';
	if ((sz = strlcpy(buf, "append-string \"", len)) >= len)
		return;
	buf += sz;
	len -= sz;
	
	sz = strnvis(buf, t->data, len, VIS_CSTYLE|VIS_TAB|VIS_NL);
	if (sz >= len)
		return;
	buf += sz;
	len -= sz;

	if (len >= 2) {
		buf[0] = '"';
		buf[1] = '\0';
	}
}
