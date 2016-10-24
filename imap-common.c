/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicholas.marriott@gmail.com>
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
#include <netinet/in.h>
#include <arpa/nameser.h>

#include <ctype.h>
#include <resolv.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "fdm.h"
#include "fetch.h"

void	imap_free(void *);

int	imap_parse(struct account *, int, char *);

char   *imap_base64_encode(char *);
char   *imap_base64_decode(char *);

int	imap_pick_auth(struct account *, struct fetch_ctx *);

int	imap_state_connect(struct account *, struct fetch_ctx *);
int	imap_state_capability1(struct account *, struct fetch_ctx *);
int	imap_state_capability2(struct account *, struct fetch_ctx *);
int	imap_state_starttls(struct account *, struct fetch_ctx *);
int	imap_state_cram_md5_auth(struct account *, struct fetch_ctx *);
int	imap_state_login(struct account *, struct fetch_ctx *);
int	imap_state_user(struct account *, struct fetch_ctx *);
int	imap_state_pass(struct account *, struct fetch_ctx *);
int	imap_state_select2(struct account *, struct fetch_ctx *);
int	imap_state_select3(struct account *, struct fetch_ctx *);
int	imap_state_select4(struct account *, struct fetch_ctx *);
int	imap_state_search1(struct account *, struct fetch_ctx *);
int	imap_state_search2(struct account *, struct fetch_ctx *);
int	imap_state_search3(struct account *, struct fetch_ctx *);
int	imap_state_next(struct account *, struct fetch_ctx *);
int	imap_state_body(struct account *, struct fetch_ctx *);
int	imap_state_line(struct account *, struct fetch_ctx *);
int	imap_state_mail(struct account *, struct fetch_ctx *);
int	imap_state_gmext_start(struct account *, struct fetch_ctx *);
int	imap_state_gmext_body(struct account *, struct fetch_ctx *);
int	imap_state_gmext_done(struct account *, struct fetch_ctx *);
int	imap_state_commit(struct account *, struct fetch_ctx *);
int	imap_state_expunge(struct account *, struct fetch_ctx *);
int	imap_state_close(struct account *, struct fetch_ctx *);
int	imap_state_quit(struct account *, struct fetch_ctx *);

/* Put line to server. */
int
imap_putln(struct account *a, const char *fmt, ...)
{
	struct fetch_imap_data	*data = a->data;
	va_list			 ap;
	int			 n;

	va_start(ap, fmt);
	n = data->putln(a, fmt, ap);
	va_end(ap);

	return (n);
}

/*
 * Get line from server. Returns -1 on error, 0 on success, a NULL line when
 * out of data.
 */
int
imap_getln(struct account *a, struct fetch_ctx *fctx, int type, char **line)
{
	struct fetch_imap_data	*data = a->data;
	int			 n;

	do {
		if (data->getln(a, fctx, line) != 0)
			return (-1);
		if (*line == NULL)
			return (0);
	} while ((n = imap_parse(a, type, *line)) == 1);
	return (n);
}

/* Free auxiliary data. */
void
imap_free(void *ptr)
{
	xfree(ptr);
}

/* Check for okay from server. */
int
imap_okay(char *line)
{
	char	*ptr;

	ptr = strchr(line, ' ');
	if (ptr == NULL)
		return (0);
	if (ptr[1] != 'O' || ptr[2] != 'K' || (ptr[3] != ' ' && ptr[3] != '\0'))
		return (0);
	return (1);
}

/* Check for no from server. */
int
imap_no(char *line)
{
	char	*ptr;

	ptr = strchr(line, ' ');
	if (ptr == NULL)
		return (0);
	if (ptr[1] != 'N' || ptr[2] != 'O' || (ptr[3] != ' ' && ptr[3] != '\0'))
		return (0);
	return (1);
}

/*
 * Parse line based on type. Returns -1 on error, 0 on success, 1 to ignore
 * this line.
 */
int
imap_parse(struct account *a, int type, char *line)
{
	struct fetch_imap_data	*data = a->data;
	int			 tag;

	if (type == IMAP_RAW)
		return (0);

	tag = imap_tag(line);
	switch (type) {
	case IMAP_TAGGED:
		if (tag == IMAP_TAG_NONE)
			return (1);
		if (tag == IMAP_TAG_CONTINUE)
			goto invalid;
		if (tag != data->tag)
			goto invalid;
		break;
	case IMAP_UNTAGGED:
		if (tag != IMAP_TAG_NONE)
			goto invalid;
		break;
	case IMAP_CONTINUE:
		if (tag == IMAP_TAG_NONE)
			return (1);
		if (tag != IMAP_TAG_CONTINUE)
			goto invalid;
		break;
	}

	return (0);

invalid:
	imap_bad(a, line);
	return (-1);
}

/* Parse IMAP tag. */
int
imap_tag(char *line)
{
	int		 tag;
	const char	*errstr;
	char		*ptr;

	if (line[0] == '*' && line[1] == ' ')
		return (IMAP_TAG_NONE);
	if (line[0] == '+')
		return (IMAP_TAG_CONTINUE);

	if ((ptr = strchr(line, ' ')) == NULL)
		ptr = strchr(line, '\0');
	*ptr = '\0';

	tag = strtonum(line, 0, INT_MAX, &errstr);
	*ptr = ' ';
	if (errstr != NULL)
		return (IMAP_TAG_ERROR);

	return (tag);
}

/* Base64 encode string. */
char *
imap_base64_encode(char *in)
{
	char	*out;
	size_t	 size;

	size = (strlen(in) * 2) + 1;
	out = xcalloc(1, size);
	if (b64_ntop(in, strlen(in), out, size) < 0) {
		xfree(out);
		return (NULL);
	}
	return (out);
}

/* Base64 decode string. */
char *
imap_base64_decode(char *in)
{
	char	*out;
	size_t	 size;

	size = (strlen(in) * 4) + 1;
	out = xcalloc(1, size);
	if (b64_pton(in, out, size) < 0) {
		xfree(out);
		return (NULL);
	}
	return (out);
}

int
imap_bad(struct account *a, const char *line)
{
	log_warnx("%s: unexpected data: %s", a->name, line);
	return (FETCH_ERROR);
}

int
imap_invalid(struct account *a, const char *line)
{
	log_warnx("%s: invalid response: %s", a->name, line);
	return (FETCH_ERROR);
}

/* Commit mail. */
int
imap_commit(struct account *a, struct mail *m)
{
	struct fetch_imap_data	*data = a->data;
	struct fetch_imap_mail	*aux = m->auxdata;

	if (m->decision == DECISION_DROP)
		ARRAY_ADD(&data->dropped, aux->uid);
	else
		ARRAY_ADD(&data->kept, aux->uid);

	xfree(aux);
	m->auxdata = m->auxfree = NULL;

	return (FETCH_AGAIN);
}

/* Abort fetch. */
void
imap_abort(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	ARRAY_FREE(&data->dropped);
	ARRAY_FREE(&data->kept);
	ARRAY_FREE(&data->wanted);

	data->disconnect(a);
}

/* Return total mails available. */
u_int
imap_total(struct account *a)
{
	struct fetch_imap_data	*data = a->data;

	return (data->folders_total);
}

/* Try an authentication method. */
int
imap_pick_auth(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	/* Try CRAM-MD5, if server supports it and user allows it. */
	if (!data->nocrammd5 && (data->capa & IMAP_CAPA_AUTH_CRAM_MD5)) {
		if (imap_putln(a,
		    "%u AUTHENTICATE CRAM-MD5", ++data->tag) != 0)
			return (FETCH_ERROR);
		fctx->state = imap_state_cram_md5_auth;
		return (FETCH_BLOCK);
	}

	/* Fall back to LOGIN, unless config disallows it. */
	if (!data->nologin) {
		if (imap_putln(a,
		    "%u LOGIN {%zu}", ++data->tag, strlen(data->user)) != 0)
			return (FETCH_ERROR);
		fctx->state = imap_state_login;
		return (FETCH_BLOCK);
	}

	log_warnx("%s: no authentication methods", a->name);
	return (FETCH_ERROR);
}

/* Common initialisation state. */
int
imap_state_init(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	ARRAY_INIT(&data->dropped);
	ARRAY_INIT(&data->kept);
	ARRAY_INIT(&data->wanted);

	data->tag = 0;

	data->folder = 0;
	data->folders_total = 0;

	fctx->state = imap_state_connect;
	return (FETCH_AGAIN);
}

/* Connect state. */
int
imap_state_connect(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	if (data->connect(a) != 0)
		return (FETCH_ERROR);

	fctx->state = imap_state_connected;
	return (FETCH_BLOCK);
}

/* Connected state: wait for initial line from server. */
int
imap_state_connected(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_getln(a, fctx, IMAP_UNTAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	if (strncmp(line, "* PREAUTH", 9) == 0) {
		fctx->state = imap_state_select1;
		return (FETCH_AGAIN);
	}
	if (data->user == NULL || data->pass == NULL) {
		log_warnx("%s: not PREAUTH and no user or password", a->name);
		return (FETCH_ERROR);
	}

	if (imap_putln(a, "%u CAPABILITY", ++data->tag) != 0)
		return (FETCH_ERROR);
	fctx->state = imap_state_capability1;
	return (FETCH_BLOCK);
}

/* Capability state 1. Parse capabilities and set flags. */
int
imap_state_capability1(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line, *ptr;

	if (imap_getln(a, fctx, IMAP_UNTAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	/* Convert to uppercase. */
	for (ptr = line; *ptr != '\0'; ptr++)
		*ptr = toupper((u_char) *ptr);

	if (strstr(line, "IMAP4REV1") == NULL) {
		log_warnx("%s: no IMAP4rev1 capability: %s", a->name, line);
		return (FETCH_ERROR);
	}

	data->capa = 0;
	if (strstr(line, "AUTH=CRAM-MD5") != NULL)
		data->capa |= IMAP_CAPA_AUTH_CRAM_MD5;

	/* Use XYZZY to detect Google brokenness. */
	if (strstr(line, "XYZZY") != NULL)
		data->capa |= IMAP_CAPA_XYZZY;

	/* GMail IMAP extensions. */
	if (strstr(line, "X-GM-EXT-1") != NULL)
		data->capa |= IMAP_CAPA_GMEXT;

	if (strstr(line, "STARTTLS") != NULL)
		data->capa |= IMAP_CAPA_STARTTLS;

	fctx->state = imap_state_capability2;
	return (FETCH_AGAIN);
}

/* Capability state 2. Check capabilities and choose login type. */
int
imap_state_capability2(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	if (data->starttls) {
		if (!(data->capa & IMAP_CAPA_STARTTLS)) {
			log_warnx("%s: server doesn't support STARTTLS",
			    a->name);
			return (FETCH_ERROR);
		}
		if (imap_putln(a, "%u STARTTLS", ++data->tag) != 0)
			return (FETCH_ERROR);
		fctx->state = imap_state_starttls;
		return (FETCH_BLOCK);
	}

	return (imap_pick_auth(a, fctx));
}

/* STARTTLS state. */
int
imap_state_starttls(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line, *cause;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	data->io->ssl = makessl(&data->server, data->io->fd,
	    conf.verify_certs && data->server.verify, conf.timeout, &cause);
	if (data->io->ssl == NULL) {
		log_warnx("%s: STARTTLS failed: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}

	return (imap_pick_auth(a, fctx));
}

/* CRAM-MD5 auth state. */
int
imap_state_cram_md5_auth(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line, *ptr, *src, *b64;
	char			 out[EVP_MAX_MD_SIZE * 2 + 1];
	u_char			 digest[EVP_MAX_MD_SIZE];
	u_int			 i, n;

	if (imap_getln(a, fctx, IMAP_CONTINUE, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	ptr = line + 1;
	while (isspace((u_char) *ptr))
		ptr++;
	if (*ptr == '\0')
		return (imap_invalid(a, line));

	b64 = imap_base64_decode(ptr);
	HMAC(EVP_md5(),
	    data->pass, strlen(data->pass), b64, strlen(b64), digest, &n);
	xfree(b64);

	for (i = 0; i < n; i++)
		xsnprintf(out + i * 2, 3, "%02hhx", digest[i]);
	xasprintf(&src, "%s %s", data->user, out);
	b64 = imap_base64_encode(src);
	xfree(src);

	if (imap_putln(a, "%s", b64) != 0) {
		xfree(b64);
		return (FETCH_ERROR);
	}
	xfree(b64);

	fctx->state = imap_state_pass;
	return (FETCH_BLOCK);
}

/* Login state. */
int
imap_state_login(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;
	size_t			 passlen;

	if (imap_getln(a, fctx, IMAP_CONTINUE, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	passlen = strlen(data->pass);
	if (data->capa & IMAP_CAPA_NOSPACE) {
		if (imap_putln(a, "%s{%zu}", data->user, passlen) != 0)
			return (FETCH_ERROR);
	} else {
		if (imap_putln(a, "%s {%zu}", data->user, passlen) != 0)
			return (FETCH_ERROR);
	}
	fctx->state = imap_state_user;
	return (FETCH_BLOCK);
}

/* User state. */
int
imap_state_user(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;
	int                      tag;

	if (data->capa & IMAP_CAPA_NOSPACE) {
		if (imap_getln(a, fctx, IMAP_CONTINUE, &line) != 0)
			return (FETCH_ERROR);
		if (line == NULL)
			return (FETCH_BLOCK);
	} else {
		for (;;) {
			if (imap_getln(a, fctx, IMAP_RAW, &line) != 0)
				return (FETCH_ERROR);
			if (line == NULL)
				return (FETCH_BLOCK);
			tag = imap_tag(line);
			if (tag == IMAP_TAG_NONE)
				continue;
			if (tag == IMAP_TAG_CONTINUE || tag == data->tag)
				break;
			return (FETCH_ERROR);
		}
		if (tag != IMAP_TAG_CONTINUE) {
			log_debug("%s: didn't accept user (%s); "
			    "trying without space", a->name, line);
			data->capa |= IMAP_CAPA_NOSPACE;
			return (imap_pick_auth(a, fctx));
		}
	}

	if (imap_putln(a, "%s", data->pass) != 0)
		return (FETCH_ERROR);
	fctx->state = imap_state_pass;
	return (FETCH_BLOCK);
}

/* Pass state. */
int
imap_state_pass(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	fctx->state = imap_state_select1;
	return (FETCH_AGAIN);
}

/* Select state 1. */
int
imap_state_select1(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	if (imap_putln(a, "%u SELECT {%zu}",
	    ++data->tag, strlen(ARRAY_ITEM(data->folders, data->folder))) != 0)
		return (FETCH_ERROR);
	fctx->state = imap_state_select2;
	return (FETCH_BLOCK);
}

/* Select state 2. Wait for continuation and send folder name. */
int
imap_state_select2(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_getln(a, fctx, IMAP_CONTINUE, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	if (imap_putln(a, "%s", ARRAY_ITEM(data->folders, data->folder)) != 0)
		return (FETCH_ERROR);
	fctx->state = imap_state_select3;
	return (FETCH_BLOCK);
}

/* Select state 3. Hold until select returns message count. */
int
imap_state_select3(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	for (;;) {
		if (imap_getln(a, fctx, IMAP_UNTAGGED, &line) != 0)
			return (FETCH_ERROR);
		if (line == NULL)
			return (FETCH_BLOCK);

		if (sscanf(line, "* %u EXISTS", &data->total) == 1)
			break;
	}

	fctx->state = imap_state_select4;
	return (FETCH_AGAIN);
}

/* Select state 4. Hold until select completes. */
int
imap_state_select4(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	/* If no mails, stop early. */
	if (data->total == 0) {
		if (imap_putln(a, "%u CLOSE", ++data->tag) != 0)
			return (FETCH_ERROR);
		fctx->state = imap_state_close;
		return (FETCH_BLOCK);
	}

	fctx->state = imap_state_search1;
	return (FETCH_AGAIN);
}

/* Search state 1. Request list of mail required. */
int
imap_state_search1(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	/* Search for a list of the mail UIDs to fetch. */
	switch (data->only) {
	case FETCH_ONLY_NEW:
		if (imap_putln(a, "%u UID SEARCH UNSEEN", ++data->tag) != 0)
			return (FETCH_ERROR);
		break;
	case FETCH_ONLY_OLD:
		if (imap_putln(a, "%u UID SEARCH SEEN", ++data->tag) != 0)
			return (FETCH_ERROR);
		break;
	default:
		if (imap_putln(a, "%u UID SEARCH ALL", ++data->tag) != 0)
			return (FETCH_ERROR);
		break;
	}

	fctx->state = imap_state_search2;
	return (FETCH_BLOCK);
}

/* Search state 2. */
int
imap_state_search2(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line, *ptr;
	u_int			 uid;

	if (imap_getln(a, fctx, IMAP_UNTAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	/* Skip the header. */
	if (strncasecmp(line, "* SEARCH", 8) != 0)
		return (imap_bad(a, line));
	line += 8;

	/* Read each UID and save it. */
	do {
		while (isspace((u_char) *line))
			line++;
		ptr = strchr(line, ' ');
		if (ptr == NULL)
			ptr = strchr(line, '\0');
		if (ptr == line)
			break;

		if (sscanf(line, "%u", &uid) != 1)
			return (imap_bad(a, line));
		ARRAY_ADD(&data->wanted, uid);
		log_debug3("%s: fetching UID: %u", a->name, uid);

		line = ptr;
	} while (*line == ' ');

	fctx->state = imap_state_search3;
	return (FETCH_AGAIN);
}

/* Search state 3. */
int
imap_state_search3(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	/* Save the total. */
	data->total = ARRAY_LENGTH(&data->wanted);

	/* Update grand total. */
	data->folders_total += data->total;

	/* If no mails, or polling, stop here. */
	if (data->total == 0 || fctx->flags & FETCH_POLL) {
		if (imap_putln(a, "%u CLOSE", ++data->tag) != 0)
			return (FETCH_ERROR);
		fctx->state = imap_state_close;
		return (FETCH_BLOCK);
	}

	fctx->state = imap_state_next;
	return (FETCH_AGAIN);
}

/*
 * Next state. Get next mail. This is also the idle state when completed, so
 * check for finished mail, exiting, and so on.
 */
int
imap_state_next(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;

	/* Handle dropped and kept mail. */
	if (!ARRAY_EMPTY(&data->dropped)) {
		if (imap_putln(a, "%u UID STORE %u +FLAGS.SILENT (\\Deleted)",
		    ++data->tag, ARRAY_FIRST(&data->dropped)) != 0)
			return (FETCH_ERROR);
		ARRAY_REMOVE(&data->dropped, 0);
		fctx->state = imap_state_commit;
		return (FETCH_BLOCK);
	}
	if (!ARRAY_EMPTY(&data->kept)) {
		/*
		 * GMail is broken and does not set the \Seen flag after mail
		 * is fetched, so set it explicitly for kept mail.
		 */
		if (imap_putln(a, "%u UID STORE %u +FLAGS.SILENT (\\Seen)",
		    ++data->tag, ARRAY_FIRST(&data->kept)) != 0)
			return (FETCH_ERROR);
		ARRAY_REMOVE(&data->kept, 0);
		fctx->state = imap_state_commit;
		return (FETCH_BLOCK);
	}

	/* Need to purge, switch to purge state. */
	if (fctx->flags & FETCH_PURGE) {
		/*
		 * If can't purge now, loop through this state until there is
		 * no mail on the dropped queue and FETCH_EMPTY is set. Can't
		 * have a seperate state to loop through without returning
		 * here: mail could potentially be added to the dropped list
		 * while in that state.
		 */
		if (fctx->flags & FETCH_EMPTY) {
			fctx->flags &= ~FETCH_PURGE;

			if (imap_putln(a, "%u EXPUNGE", ++data->tag) != 0)
				return (FETCH_ERROR);
			fctx->state = imap_state_expunge;
			return (FETCH_BLOCK);
		}

		/*
		 * Must be waiting for delivery, so permit blocking even though
		 * we (fetch) aren't waiting for any data.
		 */
		return (FETCH_BLOCK);
	}

	/* If last mail, wait for everything to be committed then close down. */
	if (ARRAY_EMPTY(&data->wanted)) {
		if (data->committed != data->total)
			return (FETCH_BLOCK);
		if (imap_putln(a, "%u CLOSE", ++data->tag) != 0)
			return (FETCH_ERROR);
		fctx->state = imap_state_close;
		return (FETCH_BLOCK);
	}

	/* Fetch the next mail. */
	if (imap_putln(a, "%u "
	    "UID FETCH %u BODY[]",++data->tag, ARRAY_FIRST(&data->wanted)) != 0)
		return (FETCH_ERROR);
	fctx->state = imap_state_body;
	return (FETCH_BLOCK);
}

/* Body state. */
int
imap_state_body(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	struct mail		*m = fctx->mail;
	struct fetch_imap_mail	*aux;
	char			*line, *ptr;
	u_int			 n;

	if (imap_getln(a, fctx, IMAP_UNTAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);

	if (sscanf(line, "* %u FETCH (", &n) != 1)
		return (imap_invalid(a, line));
	if ((ptr = strstr(line, "BODY[] {")) == NULL)
		return (imap_invalid(a, line));

	if (sscanf(ptr, "BODY[] {%zu}", &data->size) != 1)
		return (imap_invalid(a, line));
	data->lines = 0;

	/* Fill in local data. */
	aux = xcalloc(1, sizeof *aux);
	aux->uid = ARRAY_FIRST(&data->wanted);
	m->auxdata = aux;
	m->auxfree = imap_free;
	ARRAY_REMOVE(&data->wanted, 0);

	/* Open the mail. */
	if (mail_open(m, data->size) != 0) {
		log_warnx("%s: failed to create mail", a->name);
		return (FETCH_ERROR);
	}
	m->size = 0;

	/* Tag mail. */
	default_tags(&m->tags, data->src);
	if (data->server.host != NULL) {
		add_tag(&m->tags, "server", "%s", data->server.host);
		add_tag(&m->tags, "port", "%s", data->server.port);
	}
	add_tag(&m->tags, "server_uid", "%u", aux->uid);
	add_tag(&m->tags,
	    "folder", "%s", ARRAY_ITEM(data->folders, data->folder));

	/* If we already know the mail is oversize, start off flushing it. */
	data->flushing = data->size > conf.max_size;

	fctx->state = imap_state_line;
	return (FETCH_AGAIN);
}

/* Line state. */
int
imap_state_line(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	struct mail		*m = fctx->mail;
	char			*line;
	size_t			 used, size, left;

	for (;;) {
		if (imap_getln(a, fctx, IMAP_RAW, &line) != 0)
			return (FETCH_ERROR);
		if (line == NULL)
			return (FETCH_BLOCK);

		if (data->flushing)
			continue;

		/* Check if this line would exceed the expected size. */
		used = m->size + data->lines;
		size = strlen(line);
		if (used + size + 2 > data->size)
			break;

		if (append_line(m, line, size) != 0) {
			log_warnx("%s: failed to resize mail", a->name);
			return (FETCH_ERROR);
		}
		data->lines++;
	}

	/*
	 * Calculate the number of bytes still needed. The current line must
	 * include at least that much data. Some servers include UID or FLAGS
	 * after the message: we don't care about these so just ignore them and
	 * make sure there is a terminating ).
	 */
	left = data->size - used;
	if (line[size - 1] != ')' && size <= left)
		return (imap_invalid(a, line));

	/* If there was data left, add it as a new line without trailing \n. */
	if (left > 0) {
		if (append_line(m, line, left) != 0) {
			log_warnx("%s: failed to resize mail", a->name);
			return (FETCH_ERROR);
		}
		data->lines++;

		/* Wipe out the trailing \n. */
		m->size--;
	}

	fctx->state = imap_state_mail;
	return (FETCH_AGAIN);
}

/* Mail state. */
int
imap_state_mail(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char	*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	if (data->capa & IMAP_CAPA_GMEXT) {
		fctx->state = imap_state_gmext_start;
		return (FETCH_AGAIN);
	}

	fctx->state = imap_state_next;
	return (FETCH_MAIL);
}

/* GMail extensions start state. */
int
imap_state_gmext_start(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	struct mail		*m = fctx->mail;
	struct fetch_imap_mail	*aux = m->auxdata;

	if (imap_putln(a, "%u FETCH %u (X-GM-MSGID X-GM-THRID X-GM-LABELS)",
	    ++data->tag, aux->uid) != 0)
		return (FETCH_ERROR);

	fctx->state = imap_state_gmext_body;
	return (FETCH_AGAIN);
}

/* GMail extensions body state. */
int
imap_state_gmext_body(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	struct mail		*m = fctx->mail;
	char			*line, *lb;
	int     	         tag;
	u_int			 n;
	uint64_t		 thrid, msgid;
	size_t			 lblen;

	for (;;) {
		if (imap_getln(a, fctx, IMAP_RAW, &line) != 0)
			return (FETCH_ERROR);
		if (line == NULL)
			return (FETCH_BLOCK);
		tag = imap_tag(line);
		if (tag == IMAP_TAG_NONE)
			break;
		if (tag == data->tag) {
			fctx->state = imap_state_next;
			return (FETCH_MAIL);
		}
		return (FETCH_ERROR);
	}

	if (sscanf(line, "* %u FETCH (X-GM-THRID %llu X-GM-MSGID %llu ", &n,
	    &thrid, &msgid) != 3)
		return (imap_invalid(a, line));
	if ((lb = strstr(line, "X-GM-LABELS")) == NULL)
		return (imap_invalid(a, line));
	if ((lb = strchr(lb, '(')) == NULL)
		return (imap_invalid(a, line));
	lb++; /* drop '(' */
	lblen = strlen(lb);
	if (lblen < 2 || lb[lblen - 1] != ')' || lb[lblen - 2] != ')')
		return (imap_invalid(a, line));
	lblen -= 2; /* drop '))' from the end */

	add_tag(&m->tags, "gmail_msgid", "%llu", msgid);
	add_tag(&m->tags, "gmail_thrid", "%llu", thrid);
	add_tag(&m->tags, "gmail_labels", "%.*s", (int)lblen, lb);

	fctx->state = imap_state_gmext_done;
	return (FETCH_AGAIN);
}

/* GMail extensions done state. */
int
imap_state_gmext_done(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	fctx->state = imap_state_next;
	return (FETCH_MAIL);
}

/* Commit state. */
int
imap_state_commit(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	data->committed++;

	fctx->state = imap_state_next;
	return (FETCH_AGAIN);
}

/* Expunge state. */
int
imap_state_expunge(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	fctx->state = imap_state_next;
	return (FETCH_AGAIN);
}

/* Close state. */
int
imap_state_close(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_imap_data	*data = a->data;
	char			*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	data->folder++;
	if (data->folder != ARRAY_LENGTH(data->folders)) {
		fctx->state = imap_state_select1;
		return (FETCH_AGAIN);
	}

	if (imap_putln(a, "%u LOGOUT", ++data->tag) != 0)
		return (FETCH_ERROR);
	fctx->state = imap_state_quit;
	return (FETCH_BLOCK);
}

/* Quit state. */
int
imap_state_quit(struct account *a, struct fetch_ctx *fctx)
{
	char	*line;

	if (imap_getln(a, fctx, IMAP_TAGGED, &line) != 0)
		return (FETCH_ERROR);
	if (line == NULL)
		return (FETCH_BLOCK);
	if (!imap_okay(line))
		return (imap_bad(a, line));

	imap_abort(a);
	return (FETCH_EXIT);
}
