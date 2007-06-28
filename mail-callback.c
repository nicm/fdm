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

/* Transform a mail in some obvious ways. */
void
transform_mail(struct account *a, unused struct fetch_ctx *fctx, struct mail *m)
{
	char		*hdr, rtm[64], *rnm;
	u_int		 lines;
	size_t		 len;
	int		 error;
 	struct tm	*tm;
	time_t		 t;

	/* Trim "From" line. */
	trim_from(m);
	if (m->size == 0)
		return;

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
		add_tag(&m->tags, "mail_dayofweek", "%d", tm->tm_wday);
		add_tag(&m->tags, "mail_dayofyear", "%.2d", tm->tm_yday);
		add_tag(&m->tags,
		    "mail_quarter", "%d", (tm->tm_mon - 1) / 3 + 1);
	}

	/* Insert message-id tag. */
	hdr = find_header(m, "message-id", &len, 1);
	if (hdr == NULL || len == 0 || len > INT_MAX)
		log_debug2("%s: message-id not found", a->name);
	else {
		log_debug2("%s: message-id is: %.*s", a->name, (int) len, hdr);
		add_tag(&m->tags, "message_id", "%.*s", (int) len, hdr);
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
		if (rfc822time(time(NULL), rtm, sizeof rtm) != NULL) {
			rnm = conf.info.fqdn;
			if (rnm == NULL)
				rnm = conf.info.host;

			error = insert_header(m, "received", "Received: by "
			    "%.450s (%s " BUILD ", account \"%.450s\");\n\t%s",
			    rnm, __progname, a->name, rtm);
		}
		if (error != 0)
			log_debug3("%s: couldn't add received header", a->name);
	}

	/* Fill wrapped line list. */
	lines = fill_wrapped(m);
	log_debug2("%s: found %u wrapped lines", a->name, lines);
}

/*
 * Create an mctx for a mail and enqueue it onto the fetch queue. Called from
 * the fetch code itself.
 */
int
enqueue_mail(struct account *a, struct fetch_ctx *fctx, struct mail *m)
{
	struct mail_ctx	*mctx;

	/* Fill in our bits of the mail. */
	m->decision = DECISION_DROP;
	m->idx = ++a->idx;
	m->tim = get_time();

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
		log_debug("%s: got message %u of %d: size %zu, body %zd",
		    a->name, m->idx, a->fetch->total(a), m->size, m->body);
	} else {
		log_debug("%s: got message %u: size %zu, body %zd", a->name,
		    m->idx, m->size, m->body);
	}
	return (0);
}

/* Handle an empty mail. */
int
empty_mail(struct account *a, unused struct fetch_ctx *fctx,
    unused struct mail *m)
{
	log_warnx("%s: empty message", a->name);

	return (-1);
}

/* Handle an oversize mail. */
int
oversize_mail(struct account *a, struct fetch_ctx *fctx, struct mail *m)
{
	struct mail_ctx	*mctx;

	log_warnx("%s: message too big: %zu bytes", a->name, m->size);

	if (conf.del_big) {
		/*
		 * Create an mctx and queue on the done queue.
		 */
		m->decision = DECISION_DROP;
		m->idx = ++a->idx;
		m->tim = get_time();

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

		TAILQ_INSERT_TAIL(&fctx->doneq, mctx, entry);
		return (0);
	}

	return (-1);
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
		fatalx("invalid decision");
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
