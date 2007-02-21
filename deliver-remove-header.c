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

int	 remove_header_deliver(struct deliver_ctx *, struct action *);
void	 remove_header_desc(struct action *, char *, size_t);

struct deliver deliver_remove_header = { DELIVER_INCHILD,
					 remove_header_deliver,
					 remove_header_desc };

int
remove_header_deliver(struct deliver_ctx *dctx, struct action *t)
{
	struct mail	*m = dctx->mail;
	char		*ptr;
	size_t	 	 len, off, wrap;
	u_int		 i;

	/* XXX necessary? */
	ARRAY_FREE(&m->wrapped);
	fill_wrapped(m);

	set_wrapped(m, ' ');

	while ((ptr = find_header(m, t->data, &len, 0)) != NULL) {
		log_debug("found header to remove: %.*s", (int) len, ptr);
		
		/* include the \n */
		len++;
		
		/* remove the header */
		memmove(ptr, ptr + len, m->size - len - (ptr - m->data));
		m->size -= len;
		if (m->body != -1)
			m->body -= len;
	
		/* fix up the wrapped array */
		off = ptr - m->data;
		i = 0;
		while (i < ARRAY_LENGTH(&m->wrapped)) {
			wrap = ARRAY_ITEM(&m->wrapped, i, size_t);
			if (wrap >= off + len) {
				ARRAY_SET(&m->wrapped, i, wrap - len, size_t);
				i++;
			} else if (wrap >= off)
				ARRAY_REMOVE(&m->wrapped, i, size_t);
			else
				i++;
		}
	}

	/* invalidate the pmatch data since stuff may have moved */
	*dctx->pm_valid = 0;
	
	set_wrapped(m, '\n');
	return (DELIVER_SUCCESS);
}

void
remove_header_desc(struct action *t, char *buf, size_t len)
{
	xsnprintf(buf, len, "remove-header \"%s\"", (char *) t->data);
}
