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

#include "fdm.h"

int	command_match(struct account *, struct mail *, struct expritem *);
char   *command_desc(struct expritem *);

struct match match_command = { "command", command_match, command_desc };

int
command_match(struct account *a, struct mail *m, struct expritem *ei)
{
	struct command_data	*data;

	data = ei->data;

	/** **/
	
	return (0);
}

char *
command_desc(struct expritem *ei)
{
	struct command_data	*data;
	char			*s, ret[11];

	data = ei->data;

	*ret = '\0';
	if (data->ret != -1)
		snprintf(ret, sizeof ret, "%d", data->ret);

	if (data->re_s == NULL)
		xasprintf(&s, "`%s` returns (%s, )", data->cmd, ret);
	else {
		xasprintf(&s, "`%s` returns (%s, \"%s\")", data->cmd, ret,
		    data->re_s);
	}
	return (s);
}
