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

#include <string.h>

#include "fdm.h"
#include "fetch.h"

int	imap_okay(struct account *, char *);

int
imap_tag(char *line)
{
	long	 	 tag;
	const char	*errstr;
	char		*ptr;

	if (line[0] == '*' && line[1] == ' ')
		return (IMAP_TAG_NONE);
	if (line[0] == '+')
		return (IMAP_TAG_CONTINUE);

	if ((ptr = strchr(line, ' ')) == NULL)
		return (IMAP_TAG_ERROR);
	*ptr = '\0';

	tag = strtonum(line, 0, INT_MAX, &errstr);
	*ptr = ' ';
	if (errstr != NULL)
		return (IMAP_TAG_ERROR);

	return (tag);
}

int
imap_okay(struct account *a, char *line)
{
	char	*ptr;

	ptr = strchr(line, ' ');
	if (ptr == NULL || strncmp(ptr + 1, "OK ", 3) != 0) {
		log_warnx("%s: unexpected data: %s", a->name, line);
		return (0);
	}

	return (1);
}

int
imap_start(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	ARRAY_INIT(&data->kept);

	data->llen = IO_LINESIZE;
	data->lbuf = xmalloc(data->llen);

	data->tag = 0;

	return (FETCH_SUCCESS);
}

int
imap_finish(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	ARRAY_FREE(&data->kept);

	xfree(data->lbuf);

	return (FETCH_SUCCESS);
}

int
imap_login(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if ((line = data->getln(a, IMAP_UNTAGGED)) == NULL)
		return (1);
	if (strncmp(line, "* PREAUTH", 9) == 0)
		return (0);

	if (data->user == NULL || data->pass == NULL) {
		log_warnx("%s: not PREAUTH and no user/pass specified",
		    a->name);
		return (1);
	}

	if (data->putln(a, "%u LOGIN {%zu}", ++data->tag,
	    strlen(data->user)) != 0)
		return (1);
	if ((line = data->getln(a, IMAP_CONTINUE)) == NULL)
		return (1);
	if (data->putln(a, "%s {%zu}", data->user, strlen(data->pass)) != 0)
		return (1);
	if ((line = data->getln(a, IMAP_CONTINUE)) == NULL)
		return (1);
	if (data->putln(a, "%s", data->pass) != 0)
		return (1);
	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (1);
	if (!imap_okay(a, line))
		return (1);

	return (0);
}

int
imap_select(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (data->putln(a, "%u SELECT %s", ++data->tag, data->folder) != 0)
		return (1);
	do {
		if ((line = data->getln(a, IMAP_UNTAGGED)) == NULL)
			return (1);
	} while (sscanf(line, "* %u EXISTS", &data->num) != 1);
	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (1);
	if (!imap_okay(a, line))
		return (1);
	data->cur = 0;

	return (0);
}

int
imap_close(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (data->putln(a, "%u CLOSE", ++data->tag) != 0)
		return (1);
	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (1);
	if (!imap_okay(a, line))
		return (1);

	return (0);
}

int
imap_logout(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (data->putln(a, "%u LOGOUT", ++data->tag) != 0)
		return (1);
	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (1);
	if (!imap_okay(a, line))
		return (1);

	return (0);
}

void
imap_abort(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	data->putln(a, "%u LOGOUT", ++data->tag);
	data->flush(a);
}

int
imap_poll(struct account *a, u_int *n)
{
	struct fetch_imap_data	*data = a->data;

	*n = data->num;

	return (FETCH_SUCCESS);
}

int
imap_fetch(struct account *a, struct mail *m)
{
	struct fetch_imap_data	*data = a->data;
	char			*line, *ptr;
	u_int	 		 n, i, lines;
	size_t	 		 size, off, len;
	int	 		 flushing, bodylines;

	data->cur++;
	if (data->cur > data->num)
		return (FETCH_COMPLETE);

restart:
	/* find and save the uid */
	if (data->putln(a, "%u FETCH %u UID", ++data->tag, data->cur) != 0)
		return (FETCH_ERROR);
	if ((line = data->getln(a, IMAP_UNTAGGED)) == NULL)
		return (FETCH_ERROR);
	if (sscanf(line, "* %u FETCH (UID %u)", &n, &data->uid) != 2) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (FETCH_ERROR);
	}
	if (n != data->cur) {
 		log_warnx("%s: message index incorrect: %s", a->name, line);
		return (FETCH_ERROR);
	}
	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (FETCH_ERROR);
	if (!imap_okay(a, line))
		return (FETCH_ERROR);

	for (i = 0; i < ARRAY_LENGTH(&data->kept); i++) {
		if (ARRAY_ITEM(&data->kept, i, u_int) == data->uid) {
			/* seen this message before and kept it, so skip it */
			data->cur++;
			if (data->cur > data->num)
				return (FETCH_COMPLETE);
			goto restart;
		}
	}

	/* fetch the mail */
	if (data->putln(a, "%u FETCH %u BODY[]", ++data->tag, data->cur) != 0)
		return (FETCH_ERROR);
	if ((line = data->getln(a, IMAP_UNTAGGED)) == NULL)
		return (FETCH_ERROR);

	if (sscanf(line, "* %u FETCH (", &n) != 1) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (FETCH_ERROR);
	}
	if ((ptr = strstr(line, "BODY[] {")) == NULL) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (FETCH_ERROR);
	}

	if (sscanf(ptr, "BODY[] {%zu}", &size) != 1) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (FETCH_ERROR);
	}
	if (n != data->cur) {
 		log_warnx("%s: message index incorrect: %s", a->name, line);
		return (FETCH_ERROR);
	}
	if (size == 0)
		return (FETCH_EMPTY);

	mail_open(m, IO_ROUND(size));
	default_tags(&m->tags, data->server.host, a);
	if (data->server.host != NULL) {
		add_tag(&m->tags, "server", "%s", data->server.host);
		add_tag(&m->tags, "port", "%s", data->server.port);
	}
	add_tag(&m->tags, "server_uid", "%u", data->uid);
	add_tag(&m->tags, "folder", "%s", data->folder);

	flushing = 0;
	if (size > conf.max_size)
		flushing = 1;
	off = lines = 0;
	bodylines = -1;
	for (;;) {
		if ((line = data->getln(a, IMAP_RAW)) == NULL)
			return (FETCH_ERROR);

		len = strlen(line);
		if (len == 0 && m->body == -1) {
			m->body = off + 1;
			bodylines = 0;
		}

		if (!flushing) {
			resize_mail(m, off + len + 1);

			if (len > 0)
				memcpy(m->data + off, line, len);
			m->data[off + len] = '\n';
		}

		lines++;
		if (bodylines != -1)
			bodylines++;
		off += len + 1;
		if (off + lines >= size)
			break;
	}

	if ((line = data->getln(a, IMAP_RAW)) == NULL)
		return (FETCH_ERROR);
	if (strcmp(line, ")") != 0) {
 		log_warnx("%s: invalid response: %s", a->name, line);
		return (FETCH_ERROR);
	}

	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (FETCH_ERROR);
	if (!imap_okay(a, line))
		return (FETCH_ERROR);
	if (off + lines != size) {
 		log_warnx("%s: received too much data", a->name);
		return (FETCH_ERROR);
	}
	m->size = off;

	add_tag(&m->tags, "lines", "%u", lines);
	if (bodylines == -1) {
		add_tag(&m->tags, "body_lines", "0");
		add_tag(&m->tags, "header_lines", "%u", lines - 1);
	} else {
		add_tag(&m->tags, "body_lines", "%d", bodylines - 1);
		add_tag(&m->tags, "header_lines", "%d", lines - bodylines);
	}

	if (flushing)
		return (FETCH_OVERSIZE);
	return (FETCH_SUCCESS);
}

int
imap_done(struct account *a, enum decision d)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (d == DECISION_KEEP) {
		ARRAY_ADD(&data->kept, data->uid, u_int);
		return (FETCH_SUCCESS);
	}

	if (data->putln(a, "%u STORE %u +FLAGS \\Deleted", ++data->tag,
	    data->cur) != 0)
		return (FETCH_ERROR);
	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (FETCH_ERROR);
	if (!imap_okay(a, line))
		return (FETCH_ERROR);

	return (FETCH_SUCCESS);
}

int
imap_purge(struct account *a)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (data->putln(a, "%u EXPUNGE", ++data->tag) != 0)
		return (FETCH_ERROR);
	if ((line = data->getln(a, IMAP_TAGGED)) == NULL)
		return (FETCH_ERROR);
	if (!imap_okay(a, line))
		return (FETCH_ERROR);

	if (imap_select(a) != 0)
		return (FETCH_ERROR);

	return (FETCH_SUCCESS);
}
