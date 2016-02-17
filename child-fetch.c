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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fdm.h"
#include "deliver.h"
#include "fetch.h"
#include "match.h"

void	fetch_status(struct account *, double);
int	fetch_account(struct account *, struct io *, int, double);
int	fetch_match(struct account *, struct msg *, struct msgbuf *);
int	fetch_deliver(struct account *, struct msg *, struct msgbuf *);
int	fetch_poll(struct account *, struct iolist *, struct io *, int);
int	fetch_purge(struct account *);
void	fetch_free(void);
void	fetch_free1(struct mail_ctx *);

int	fetch_enqueue(struct account *, struct io *, struct mail *);
int	fetch_dequeue(struct account *, struct mail_ctx *);

struct mail_queue	 fetch_matchq;
struct mail_queue	 fetch_deliverq;

u_int			 fetch_dropped;
u_int			 fetch_kept;

u_int			 fetch_queued;	 /* number of mails queued */
u_int			 fetch_blocked;	 /* blocked for parent */

int
open_cache(struct account *a, struct cache *cache)
{
	int	n;

	if (cache->db != NULL)
		return (0);

	if ((cache->db = db_open(cache->path)) == NULL) {
		log_warn("%s: %s", a->name, cache->path);
		return (-1);
	}

	n = db_size(cache->db);
	log_debug3("%s: opened cache %s: %d keys", a->name, cache->path, n);

	if (cache->expire == 0)
		return (0);
	if (db_expire(cache->db, cache->expire) != 0) {
		log_warnx("%s: %s: expiry failed", a->name, cache->path);
		return (-1);
	}

	n -= db_size(cache->db);
	if (n < 0)
		n = 0;
	log_debug3("%s: cache %s: expired %d keys", a->name, cache->path, n);

	return (0);
}

int
child_fetch(struct child *child, struct io *pio)
{
	struct child_fetch_data	*data = child->data;
	enum fdmop		 op = data->op;
	struct account		*a = data->account;
	struct msg		 msg;
	int			 error, flags;
	double			 tim;

	log_debug2("%s: fetch started, pid %ld", a->name, (long) getpid());

#ifdef HAVE_SETPROCTITLE
	setproctitle("child: %s", a->name);
#endif

	log_debug2("%s: user is %lu", a->name, (u_long) geteuid());
	tim = get_time();

	/* Process fetch or poll. */
	log_debug2("%s: started processing", a->name);
	flags = 0;
	if (op == FDMOP_POLL)
		flags |= FETCH_POLL;
	error = fetch_account(a, pio, flags, tim);
	log_debug2("%s: finished processing. exiting", a->name);

	memset(&msg, 0, sizeof msg);
	msg.type = MSG_EXIT;
	log_debug3("%s: sending exit message to parent", a->name);
	if (privsep_send(pio, &msg, NULL) != 0)
		fatalx("privsep_send error");
	do {
		log_debug3("%s: waiting for exit message from parent", a->name);
		if (privsep_recv(pio, &msg, NULL) != 0)
			fatalx("privsep_recv error");
	} while (msg.type != MSG_EXIT);

	return (error);
}

int
fetch_poll(struct account *a, struct iolist *iol, struct io *pio, int timeout)
{
	struct io	*rio;
	char		*cause;
	double		 tim;

	log_debug3(
	    "%s: polling: %u, timeout=%d", a->name, ARRAY_LENGTH(iol), timeout);
	tim = get_time();
	switch (io_polln(
	    ARRAY_DATA(iol), ARRAY_LENGTH(iol), &rio, timeout, &cause)) {
	case 0:
		if (rio == pio)
			fatalx("parent socket closed");
		log_warnx("%s: connection closed", a->name);
		return (-1);
	case -1:
		if (errno == EAGAIN)
			break;
		if (rio == pio)
			fatalx("parent socket error");
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (-1);
	}
	tim = get_time() - tim;

	return (0);
}

int
fetch_match(struct account *a, struct msg *msg, struct msgbuf *msgbuf)
{
	struct mail_ctx	*mctx, *this;

	if (TAILQ_EMPTY(&fetch_matchq))
		return (0);

	mctx = TAILQ_FIRST(&fetch_matchq);
	while (mctx != NULL) {
		this = mctx;
		mctx = TAILQ_NEXT(this, entry);

		log_debug3("%s: "
		    "trying (match) message %u", a->name, this->mail->idx);
		switch (mail_match(this, msg, msgbuf)) {
		case MAIL_ERROR:
			log_debug3("%s: match"
			    " message %u, error", a->name, this->mail->idx);
			return (-1);
		case MAIL_DELIVER:
			log_debug3("%s: match"
			    " message %u, deliver", a->name, this->mail->idx);
			TAILQ_REMOVE(&fetch_matchq, this, entry);
			TAILQ_INSERT_TAIL(&fetch_deliverq, this, entry);
			break;
		case MAIL_DONE:
			log_debug3("%s: match"
			    " message %u, done", a->name, this->mail->idx);
			if (fetch_dequeue(a, this) != 0)
				return (-1);
			break;
		case MAIL_BLOCKED:
			log_debug3("%s: match"
			    " message %u, blocked", a->name, this->mail->idx);
			fetch_blocked++;
			break;
		}
	}

	return (0);
}

int
fetch_deliver(struct account *a, struct msg *msg, struct msgbuf *msgbuf)
{
	struct mail_ctx	*mctx, *this;

	if (TAILQ_EMPTY(&fetch_deliverq))
		return (0);

	mctx = TAILQ_FIRST(&fetch_deliverq);
	while (mctx != NULL) {
		this = mctx;
		mctx = TAILQ_NEXT(this, entry);

		log_debug3("%s:"
		    " trying (deliver) message %u", a->name, this->mail->idx);
		switch (mail_deliver(this, msg, msgbuf)) {
		case MAIL_ERROR:
			log_debug3("%s: deliver"
			    " message %u, error", a->name, this->mail->idx);

			if (conf.ignore_errors) {
				log_warnx("%s: fetching error. ignored",
				    a->name);

				TAILQ_REMOVE(&fetch_deliverq, this, entry);
				TAILQ_INSERT_TAIL(&fetch_matchq, this, entry);

				this->mail->decision = DECISION_KEEP;
				if (fetch_dequeue(a, this) != 0)
					return (-1);
				break;
			}

			return (-1);
		case MAIL_MATCH:
			log_debug3("%s: deliver"
			    " message %u, match", a->name, this->mail->idx);
			TAILQ_REMOVE(&fetch_deliverq, this, entry);
			TAILQ_INSERT_TAIL(&fetch_matchq, this, entry);
			break;
		case MAIL_BLOCKED:
			log_debug3("%s: deliver"
			    " message %u, blocked", a->name, this->mail->idx);
			fetch_blocked++;
			break;
		}
	}

	return (0);
}

void
fetch_free1(struct mail_ctx *mctx)
{
	struct deliver_ctx	*dctx;

	while (!TAILQ_EMPTY(&mctx->dqueue)) {
		dctx = TAILQ_FIRST(&mctx->dqueue);
		TAILQ_REMOVE(&mctx->dqueue, dctx, entry);
		user_free(dctx->udata);
		xfree(dctx);
	}

	ARRAY_FREE(&mctx->stack);
	mail_destroy(mctx->mail);
	xfree(mctx->mail);
	xfree(mctx);
}

void
fetch_free(void)
{
	struct mail_ctx	*mctx;

	while (!TAILQ_EMPTY(&fetch_matchq)) {
		mctx = TAILQ_FIRST(&fetch_matchq);
		TAILQ_REMOVE(&fetch_matchq, mctx, entry);
		fetch_free1(mctx);
	}

	while (!TAILQ_EMPTY(&fetch_deliverq)) {
		mctx = TAILQ_FIRST(&fetch_deliverq);
		TAILQ_REMOVE(&fetch_deliverq, mctx, entry);
		fetch_free1(mctx);
	}
}

int
fetch_purge(struct account *a)
{
	static u_int	last_total = 0, last_dropped = 0;
	u_int		n;

	if (conf.purge_after == 0)
		return (0);

	n = fetch_dropped + fetch_kept;
	if (n == last_total || n % conf.purge_after != 0)
		return (0);
	last_total = n;

	if (last_dropped == fetch_dropped) {
		log_debug("%s: not purging, no mails dropped", a->name);
		return (0);
	}
	last_dropped = fetch_dropped;

	log_debug("%s: purging after %u mails", a->name, n);
	return (1);
}

void
fetch_status(struct account *a, double tim)
{
	u_int	n;

	tim = get_time() - tim;
	n = fetch_dropped + fetch_kept;
	if (n > 0) {
		log_info("%s: %u messages processed (%u kept) in %.3f seconds "
		    "(average %.3f)", a->name, n, fetch_kept, tim, tim / n);
	} else {
		log_info("%s: 0 messages processed in %.3f seconds",
		    a->name, tim);
	}
}

int
fetch_account(struct account *a, struct io *pio, int nflags, double tim)
{
	struct msg	 msg, *msgp;
	struct msgbuf	 msgbuf;
	struct fetch_ctx fctx;
	struct cache	*cache;
	struct iolist	 iol;
	int		 aborted, complete, holding, timeout;

	log_debug2("%s: fetching", a->name);

	TAILQ_INIT(&fetch_matchq);
	TAILQ_INIT(&fetch_deliverq);
	fetch_queued = fetch_dropped = fetch_kept = 0;

	if (nflags & FETCH_POLL && a->fetch->total == NULL) {
		log_info("%s: polling not supported", a->name);
		return (0);
	}

	fctx.llen = IO_LINESIZE;
	fctx.lbuf = xmalloc(fctx.llen);
	fctx.flags = nflags;

	fctx.mail = xcalloc(1, sizeof *fctx.mail);
	fctx.state = a->fetch->first;

	ARRAY_INIT(&iol);

	aborted = complete = holding = 0;
	for (;;) {
		log_debug3("%s: fetch loop start", a->name);

		if (sigusr1) {
			log_debug("%s: caught SIGUSR1", a->name);
			if (!(nflags & FETCH_POLL))
				fetch_status(a, tim);
			sigusr1 = 0;
		}

		fetch_blocked = 0;

		/* Check for new privsep messages. */
		msgp = NULL;
		if (privsep_check(pio)) {
			if (privsep_recv(pio, &msg, &msgbuf) != 0)
				fatalx("privsep_recv error");
			log_debug3("%s: got message type %d, id %u", a->name,
			    msg.type, msg.id);
			msgp = &msg;
		}

		/* Match and deliver mail. */
		if (fetch_match(a, msgp, &msgbuf) != 0)
			goto abort;
		if (fetch_deliver(a, msgp, &msgbuf) != 0)
			goto abort;

		/* Check for purge and set flag if necessary. */
		if (fetch_purge(a))
			fctx.flags |= FETCH_PURGE;

		/* Update the holding flag. */
		if (fetch_queued <= (u_int) conf.queue_low)
			holding = 0;
		if (fetch_queued >= (u_int) conf.queue_high)
			holding = 1;

		/* If not holding and not finished, call the fetch handler. */
		if (!holding && !complete) {
			/*
			 * Set the empty flag if queues are empty. Purging
			 * shouldn't happen if this is clear.
			 */
			fctx.flags &= ~FETCH_EMPTY;
			if (fetch_queued == 0)
				fctx.flags |= FETCH_EMPTY;

			/* Call the fetch function. */
			log_debug3("%s: calling fetch state (%p, flags 0x%02x)",
			    a->name, fctx.state, fctx.flags);
			switch (fctx.state(a, &fctx)) {
			case FETCH_ERROR:
				/* Fetch error. */
				log_debug3("%s: fetch, error", a->name);
				goto abort;
			case FETCH_EXIT:
				/* Fetch completed. */
				log_debug3("%s: fetch, exit", a->name);
				complete = 1;
				break;
			case FETCH_AGAIN:
				/* Fetch again - no blocking. */
				log_debug3("%s: fetch, again", a->name);
				continue;
			case FETCH_BLOCK:
				/* Fetch again - allow blocking. */
				log_debug3("%s: fetch, block", a->name);
				break;
			case FETCH_MAIL:
				/* Mail ready. */
				log_debug3("%s: fetch, mail", a->name);
				if (fetch_enqueue(a, pio, fctx.mail) != 0)
					goto abort;
				fctx.mail = xcalloc(1, sizeof *fctx.mail);
				continue;
			default:
				fatalx("unexpected fetch return");
			}
		}

		/* If fetch finished and no more mails queued, exit. */
		if (complete && fetch_queued == 0)
			goto finished;

		/* Prepare for poll. */
		ARRAY_CLEAR(&iol);
		ARRAY_ADD(&iol, pio);
		if (a->fetch->fill != NULL)
			a->fetch->fill(a, &iol);

		/*
		 * Work out timeout. If the queues are empty, we can block,
		 * unless this fetch type doesn't have any sockets to poll -
		 * then we would block forever. Otherwise, if the queues are
		 * non-empty, we can block unless there are mails that aren't
		 * blocked (these mails can continue to be processed).
		 */
		timeout = conf.timeout;
		if (fetch_queued == 0 && ARRAY_LENGTH(&iol) == 1)
			timeout = 0;
		else if (fetch_queued != 0 && fetch_blocked != fetch_queued)
			timeout = 0;

		/* Poll for fetch data or privsep messages. */
		log_debug3("%s: queued %u; blocked %u; flags 0x%02x", a->name,
		    fetch_queued, fetch_blocked, fctx.flags);
		if (fetch_poll(a, &iol, pio, timeout) != 0)
			goto abort;
	}

abort:
	a->fetch->abort(a);

	if (nflags & FETCH_POLL)
		log_warnx("%s: polling error. aborted", a->name);
	else
		log_warnx("%s: fetching error. aborted", a->name);

	aborted = 1;

finished:
	if (fctx.mail != NULL) {
		mail_destroy(fctx.mail);
		xfree(fctx.mail);
	}

	xfree(fctx.lbuf);
	fetch_free();
	ARRAY_FREE(&iol);

	/* Close caches. */
	TAILQ_FOREACH(cache, &conf.caches, entry) {
		if (cache->db != NULL)
			db_close(cache->db);
	}

	/* Print results. */
	if (nflags & FETCH_POLL)
		log_info("%s: %u messages found", a->name, a->fetch->total(a));
	else
		fetch_status(a, tim);
	return (aborted);
}

/*
 * Check mail for various problems, add headers and fill tags, then create an
 * mctx and enqueue it onto the fetch queue.
 */
int
fetch_enqueue(struct account *a, struct io *pio, struct mail *m)
{
	struct mail_ctx		*mctx;
	char			*hdr, rtime[128], *rhost, total[16];
	u_int			 n, b;
	size_t			 size;
	int			 error;
	struct tm		*tm;
	time_t			 t;
	const char		*tptr;

	/*
	 * Check for oversize mails. This must be first since there is no
	 * guarantee anything other than size is valid if oversize.
	 */
	if (m->size > conf.max_size) {
		log_warnx("%s: message too big: %zu bytes", a->name, m->size);
		if (!conf.del_big)
			return (-1);

		/* Delete the mail. */
		m->decision = DECISION_DROP;
		if (a->fetch->commit != NULL &&
		    a->fetch->commit(a, m) == FETCH_ERROR)
			return (-1);

		mail_destroy(m);
		xfree(m);
		return (0);
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
		add_tag(&m->tags, "mail_month", "%.2d", tm->tm_mon + 1);
		add_tag(&m->tags, "mail_year", "%.4d", 1900 + tm->tm_year);
		add_tag(&m->tags, "mail_year2", "%.2d", tm->tm_year % 100);
		add_tag(&m->tags, "mail_dayofweek", "%d", tm->tm_wday);
		add_tag(&m->tags, "mail_dayofyear", "%.2d", tm->tm_yday + 1);
		add_tag(&m->tags,
		    "mail_quarter", "%d", tm->tm_mon / 3 + 1);
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
			rhost = conf.host_fqdn;
			if (rhost == NULL)
				rhost = conf.host_name;

			error = insert_header(m, "received", "Received: by "
			    "%.450s (%s " VERSION ", account \"%.450s\");\n\t%s",
			    rhost, __progname, a->name, rtime);
		}
		if (error != 0)
			log_debug3("%s: couldn't add received header", a->name);
	}

	/* Insert Gmail-specific headers. */
	if ((tptr = find_tag(m->tags, "gmail_msgid")) != NULL) {
		if (insert_header(m, "message-id", "X-GM-MSGID: %s", tptr) != 0)
			log_warnx("%s: failed to add header X-GM-MSGID", a->name);
	}
	if ((tptr = find_tag(m->tags, "gmail_thrid")) != NULL) {
		if (insert_header(m, "message-id", "X-GM-THRID: %s", tptr) != 0)
			log_warnx("%s: failed to add header X-GM-THRID", a->name);
	}
	if ((tptr = find_tag(m->tags, "gmail_labels")) != NULL) {
		if (insert_header(m, "message-id", "X-GM-LABELS: %s", tptr) != 0)
			log_warnx("%s: failed to add header X-GM-LABELS", a->name);
	}

	/* Fill wrapped line list. */
	n = fill_wrapped(m);
	log_debug2("%s: found %u wrapped lines", a->name, n);

	/* Create the mctx. */
	mctx = xcalloc(1, sizeof *mctx);
	mctx->account = a;
	mctx->io = pio;
	mctx->mail = m;
	mctx->msgid = 0;
	mctx->done = 0;

	mctx->matched = 0;

	mctx->rule = TAILQ_FIRST(&conf.rules);
	TAILQ_INIT(&mctx->dqueue);
	ARRAY_INIT(&mctx->stack);

	/* And enqueue it. */
	TAILQ_INSERT_TAIL(&fetch_matchq, mctx, entry);
	fetch_queued++;

	*total = '\0';
	if (a->fetch->total != NULL && a->fetch->total(a) != 0)
		xsnprintf(total, sizeof total, " of %u", a->fetch->total(a));
	log_debug("%s: got message %u%s: size %zu, body %zu", a->name, m->idx,
	    total, m->size, m->body);
	return (0);
}

/* Resolve final decision and dequeue mail. */
int
fetch_dequeue(struct account *a, struct mail_ctx *mctx)
{
	struct mail	*m = mctx->mail;

	if (conf.keep_all || a->keep)
		m->decision = DECISION_KEEP;

	switch (m->decision) {
	case DECISION_DROP:
		fetch_dropped++;
		log_debug("%s: deleting message %u", a->name, m->idx);
		break;
	case DECISION_KEEP:
		fetch_kept++;
		log_debug("%s: keeping message %u", a->name, m->idx);
		break;
	default:
		fatalx("invalid decision");
	}

	if (a->fetch->commit != NULL && a->fetch->commit(a, m) == FETCH_ERROR)
		return (-1);

	TAILQ_REMOVE(&fetch_matchq, mctx, entry);
	fetch_queued--;

	fetch_free1(mctx);

	return (0);
}
