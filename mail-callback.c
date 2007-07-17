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
#include "fetch.h"

/*
 * Check mail for various problems, add headers and fill tags, then create an
 * and enqueue it onto the fetch queue. Called from the fetch code itself.
 */
int
enqueue_mail(struct account *a, struct fetch_ctx *fctx, struct mail *m)
{
	struct mail_ctx		*mctx;
	struct mail_queue	*mq = &fctx->matchq;
	char			*hdr, rtime[128], *rhost;
	u_int		 	 n, b;
	size_t		 	 size;
	int		 	 error;
 	struct tm		*tm;
	time_t		 	 t;

	/*
	 * Check for oversize mails. This must be first since there is no
	 * guarantee anything other than size is valid if oversize.
	 */
	if (m->size > conf.max_size) {
		log_warnx("%s: message too big: %zu bytes", a->name, m->size);
		if (!conf.del_big)
			return (-1);
		/* Enqueue on done queue. */
		mq = &fctx->doneq;
		goto enqueue;
	}

 	/*
	 * Find the mail body (needed by trim_from). This is probably slower
	 * than doing it during fetching but it guarantees consistency.
	 */
	m->body = find_body(m);

 	/* Trim "From" line, if any. */
	trim_from(m);

	/* Check for empty mails. */
	if (m->size == 0) {
		log_warnx("%s: empty message", a->name);
		return (-1);
	}

	/* Fill in standard mail attributes. */
	m->decision = DECISION_DROP;
	m->idx = ++a->idx;
	m->tim = get_time();

	/* Add account name tag. */
 	add_tag(&m->tags, "account", "%s", a->name);

	/* Add mail time tags. */
	if (mailtime(m, &t) != 0) {
		log_debug2("%s: bad date header, using current time", a->name);
		t = time(NULL);
	}
	if ((tm = localtime(&t)) != NULL) {
		add_tag(&m->tags, "mail_hour", "%.2d", tm->tm_hour);
		add_tag(&m->tags, "mail_minute", "%.2d", tm->tm_min);
		add_tag(&m->tags, "mail_second", "%.2d", tm->tm_sec);
		add_tag(&m->tags, "mail_day", "%.2d", tm->tm_mday);
		add_tag(&m->tags, "mail_month", "%.2d", tm->tm_mon);
		add_tag(&m->tags, "mail_year", "%.4d", 1900 + tm->tm_year);
		add_tag(&m->tags, "mail_year2", "%.2d", tm->tm_year % 100);
		add_tag(&m->tags, "mail_dayofweek", "%d", tm->tm_wday);
		add_tag(&m->tags, "mail_dayofyear", "%.2d", tm->tm_yday);
		add_tag(&m->tags,
		    "mail_quarter", "%d", (tm->tm_mon - 1) / 3 + 1);
	}
	if (rfc822time(t, rtime, sizeof rtime) != NULL)
		add_tag(&m->tags, "mail_rfc822date", "%s", rtime);

	/* Fill in lines tags. */
	count_lines(m, &n, &b);
	log_debug2("%s: found %u lines, %u in body", a->name, n, b);
	add_tag(&m->tags, "lines", "%u", n);
	add_tag(&m->tags, "body_lines", "%u", b);
	if (n - b != 0)
		b++;	/* don't include the separator */
	add_tag(&m->tags, "header_lines", "%u", n - b);

	/* Insert message-id tag. */
	hdr = find_header(m, "message-id", &size, 1);
	if (hdr == NULL || size == 0 || size > INT_MAX)
		log_debug2("%s: message-id not found", a->name);
	else {
		log_debug2("%s: message-id is: %.*s", a->name, (int) size, hdr);
		add_tag(&m->tags, "message_id", "%.*s", (int) size, hdr);
	}

	/*
	 * Insert received header.
	 *
	 * No header line must exceed 998 bytes. Limiting the user-supplied
	 * stuff to 900 bytes gives plenty of space for the other stuff, and if
	 * it gets truncated, who cares?
	 */
	if (!conf.no_received) {
		error = 1;
		if (rfc822time(time(NULL), rtime, sizeof rtime) != NULL) {
			rhost = conf.info.fqdn;
			if (rhost == NULL)
				rhost = conf.info.host;

			error = insert_header(m, "received", "Received: by "
			    "%.450s (%s " BUILD ", account \"%.450s\");\n\t%s",
			    rhost, __progname, a->name, rtime);
		}
		if (error != 0)
			log_debug3("%s: couldn't add received header", a->name);
	}

	/* Fill wrapped line list. */
	n = fill_wrapped(m);
	log_debug2("%s: found %u wrapped lines", a->name, n);

enqueue:
	/* Create the mctx. */
	mctx = xcalloc(1, sizeof *mctx);
	mctx->account = a;
	mctx->io = fctx->io;
	mctx->mail = m;
	mctx->msgid = 0;
	mctx->done = 0;

	mctx->matched = 0;

	mctx->rule = TAILQ_FIRST(&conf.rules);
	TAILQ_INIT(&mctx->dqueue);
	ARRAY_INIT(&mctx->stack);

	/* And enqueue it. */
	TAILQ_INSERT_TAIL(&fctx->matchq, mctx, entry);
	fctx->queued++;

	if (a->fetch->total != NULL && a->fetch->total(a) > 0) {
		log_debug("%s: got message %u of %d: size %zu, body %zu",
		    a->name, m->idx, a->fetch->total(a), m->size, m->body);
	} else {
		log_debug("%s: got message %u: size %zu, body %zu", a->name,
		    m->idx, m->size, m->body);
	}
	return (0);
}

/*
 * Return first mail on the done queue. Called by fetch code when it wants to
 * delete a mail.
 */
struct mail *
done_mail(struct account *a, struct fetch_ctx *fctx)
{
	struct mail_ctx	*mctx;

	if (TAILQ_EMPTY(&fctx->doneq))
		return (NULL);

	mctx = TAILQ_FIRST(&fctx->doneq);
	if (conf.keep_all || a->keep)
		mctx->mail->decision = DECISION_KEEP;

	switch (mctx->mail->decision) {
	case DECISION_DROP:
		fctx->dropped++;
		log_debug("%s: deleting message %u", a->name, mctx->mail->idx);
		break;
	case DECISION_KEEP:
		fctx->kept++;
		log_debug("%s: keeping message %u", a->name, mctx->mail->idx);
		break;
	default:
		log_fatalx("invalid decision");
	}

	return (mctx->mail);
}

/*
 * Dequeue first mail from the done queue. Called by fetch code when it has
 * deleted mail.
 */
void
dequeue_mail(unused struct account *a, struct fetch_ctx *fctx)
{
	struct mail_ctx	*mctx;

	mctx = TAILQ_FIRST(&fctx->doneq);
	TAILQ_REMOVE(&fctx->doneq, mctx, entry);

	fetch_free1(mctx);
}

/*
 * Confirm whether or not a purge is going to lose state (there are queued
 * mails).
 */
int
can_purge(unused struct account *a, struct fetch_ctx *fctx)
{
	return (fctx->queued == 0 && TAILQ_EMPTY(&fctx->doneq));
}
