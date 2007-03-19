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

#include <fnmatch.h>

#include "fdm.h"
#include "match.h"

int	match_attachment_match(struct mail_ctx *, struct expritem *);
void	match_attachment_desc(struct expritem *, char *, size_t);

struct match match_attachment = {
	"attachment",
	match_attachment_match,
	match_attachment_desc
};

int
match_attachment_match(struct mail_ctx *mctx, struct expritem *ei)
{
	struct match_attachment_data	*data = ei->data;
	struct account			*a = mctx->account;
	struct mail			*m = mctx->mail;
	struct attach			*at;
	size_t				 size;
	u_int				 n;
	char				*value = NULL;

	if (!m->attach_built) {
		/* fill attachments */
		m->attach = attach_build(m);
		if (m->attach != NULL)
			attach_log(m->attach, "%s: attachment", a->name);
		else
			log_debug("%s: no attachments", a->name);
		m->attach_built = 1;
	}

	if (data->op == ATTACHOP_COUNT || data->op == ATTACHOP_TOTALSIZE) {
		size = 0;
		n = 0;
		at = m->attach;
		while (at != NULL) {
			size += at->size;
			n++;

			at = attach_visit(at, NULL);
		}
		switch (data->op) {
		case ATTACHOP_COUNT:
			switch (data->cmp) {
			case CMP_EQ:
				if (n == data->value.num)
					return (MATCH_TRUE);
				return (MATCH_FALSE);
			case CMP_NE:
				if (n != data->value.num)
					return (MATCH_TRUE);
				return (MATCH_FALSE);
			case CMP_LT:
				if (n < data->value.num)
					return (MATCH_TRUE);
				return (MATCH_FALSE);
			case CMP_GT:
				if (n > data->value.num)
					return (MATCH_TRUE);
				return (MATCH_FALSE);
			default:
				return (MATCH_ERROR);
			}
		case ATTACHOP_TOTALSIZE:
			switch (data->cmp) {
			case CMP_LT:
				if (size < data->value.size)
					return (MATCH_TRUE);
				return (MATCH_FALSE);
			case CMP_GT:
				if (size > data->value.size)
					return (MATCH_TRUE);
				return (MATCH_FALSE);
			default:
				return (MATCH_ERROR);
			}
		default:
			return (MATCH_ERROR);
		}
	}
	
	/* if no attachments, none of the following conditions are true */
	if (m->attach == NULL)
		return (MATCH_FALSE);
	
	/* for any type or name matches, construct the value */  
	if (data->op == ATTACHOP_ANYTYPE || data->op == ATTACHOP_ANYNAME)
		value = replacestr(&data->value.str, m->tags, m, &m->rml);

	at = m->attach;
	while (at != NULL) {
		switch (data->op) {
		case ATTACHOP_ANYSIZE:
			switch (data->cmp) {
			case CMP_LT:
				if (at->size < data->value.size)
					return (MATCH_TRUE);
				break;
			case CMP_GT:
				if (at->size > data->value.size)
					return (MATCH_TRUE);
				break;
			default:
				return (MATCH_ERROR);
			}
			break;
		case ATTACHOP_ANYTYPE:
			if (at->type == NULL)
				break;
				
			if (fnmatch(value, at->type, FNM_CASEFOLD) == 0) {
				xfree(value);
				return (MATCH_TRUE);
			}
			break;
		case ATTACHOP_ANYNAME:
			if (at->name == NULL)
				break;
			
			if (fnmatch(value, at->name, FNM_CASEFOLD) == 0) {
				xfree(value);
				return (MATCH_TRUE);
			}
			break;
		default:
			return (MATCH_ERROR);
		}
		
		at = attach_visit(at, NULL);
	}

	if (value != NULL)
		xfree(value);
	return (MATCH_FALSE);
}

void
match_attachment_desc(struct expritem *ei, char *buf, size_t len)
{
	struct match_attachment_data	*data = ei->data;
	const char 			*cmp = "";

	if (data->cmp == CMP_LT)
		cmp = "<";
	else if (data->cmp == CMP_GT)
		cmp = ">";
	else if (data->cmp == CMP_EQ)
		cmp = "==";
	else if (data->cmp == CMP_NE)
		cmp = "!=";

	switch (data->op) {
	case ATTACHOP_COUNT:
		xsnprintf(buf, len,
		    "attachment count %s %lld", cmp, data->value.num);
		break;
	case ATTACHOP_TOTALSIZE:
		xsnprintf(buf, len,
		    "attachment total-size %s %lld", cmp, data->value.num);
		break;
	case ATTACHOP_ANYSIZE:
		xsnprintf(buf, len,
		    "attachment any-size %s %lld", cmp, data->value.num);
		break;
	case ATTACHOP_ANYTYPE:
		xsnprintf(buf, len,
		    "attachment any-type \"%s\"", data->value.str.str);
		break;
	case ATTACHOP_ANYNAME:
		xsnprintf(buf, len,
		    "attachment any-name \"%s\"", data->value.str.str);
		break;
	default:
		if (len > 0)
			*buf = '\0';
		break;
	}
}
