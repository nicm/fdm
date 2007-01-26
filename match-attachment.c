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

int	attachment_match(struct match_ctx *, struct expritem *);
void	attachment_desc(struct expritem *, char *, size_t);

struct match match_attachment = { attachment_match, attachment_desc };

int
attachment_match(struct match_ctx *mctx, struct expritem *ei)
{
	struct attachment_data	*data = ei->data;
	struct mail		*m = mctx->mail;
	struct attach		*at;
	size_t			 size;
	u_int			 n;

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
	} else {
		/* if no attachments, none of these conditions are true */
		if (m->attach == NULL)
			return (MATCH_FALSE);

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
				if (fnmatch(data->value.str, at->type,
				    FNM_CASEFOLD) == 0)
					return (MATCH_TRUE);
				break;
			case ATTACHOP_ANYNAME:
				if (at->name == NULL)
					break;
				if (fnmatch(data->value.str, at->name,
				    FNM_CASEFOLD) == 0)
					return (MATCH_TRUE);
				break;
			default:
				return (MATCH_ERROR);
			}

			at = attach_visit(at, NULL);
		}

		return (MATCH_FALSE);
	}
}

void
attachment_desc(struct expritem *ei, char *buf, size_t len)
{
	struct attachment_data	*data = ei->data;
	const char 		*cmp = "";

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
		if (snprintf(buf, len, 
		    "attachment count %s %lld", cmp, data->value.num) == -1)
			fatal("snprintf");
		break;
	case ATTACHOP_TOTALSIZE:
		if (snprintf(buf, len, "attachment " 
		    "total-size %s %lld", cmp, data->value.num) == -1)
			fatal("snprintf");
		break;
	case ATTACHOP_ANYSIZE:
		if (snprintf(buf, len,
		    "attachment any-size %s %lld", cmp, data->value.num) == -1)
			fatal("snprintf");
		break;
	case ATTACHOP_ANYTYPE:
		if (snprintf(buf, len,
		    "attachment any-type \"%s\"", data->value.str) == -1)
			fatal("snprintf");
		break;
	case ATTACHOP_ANYNAME:
		if (snprintf(buf, len, 
		    "attachment any-name \"%s\"", data->value.str) == -1)
			fatal("snprintf");
		break;
	default:
		if (len > 0)
			*buf = '\0';
		break;
	}
}
