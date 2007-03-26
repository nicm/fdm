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

int	poll_account(struct io *, struct account *);
int	fetch_account(struct io *, struct account *, double);

int	fetch_drain(void);
int	fetch_done(struct mail_ctx *);
int	fetch_match(struct account *, int *, u_int *, struct msg *,
	    struct msgbuf *);
int	fetch_deliver(struct account *, int *, struct msg *, struct msgbuf *);
int	fetch_poll(struct account *, struct io *, struct mail_ctx *,
	    int, u_int);
int	fetch_get(struct account *, struct mail_ctx *, struct io *, u_int *);
int	fetch_flush(struct account *, struct io *, u_int *);
int	fetch_transform(struct account *, struct mail *);
void	fetch_free1(struct mail_ctx *);
void	fetch_free(void);

struct mail_queue 	matchq;
struct mail_queue 	deliverq;
struct mail_queue	doneq;

int			total = -1; /* total from fetch, -1 for unknown */
u_int		  	dropped;
u_int		  	kept;

int
child_fetch(struct child *child, struct io *io)
{
	struct child_fetch_data	*data = child->data;
	enum fdmop 		 op = data->op;
	struct account 		*a = data->account;
	struct msg	 	 msg;
	int			 error = 1;
	double			 tim;

#ifdef DEBUG
	xmalloc_clear();
	COUNTFDS(a->name);
#endif

	io->flags |= IO_NOWAIT;
	log_debug2("%s: fetch started, pid %ld", a->name, (long) getpid());

#ifndef NO_SETPROCTITLE
	setproctitle("child: %s", a->name);
#endif

	fill_info(NULL);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	if (op == FDMOP_POLL && a->fetch->poll == NULL) {
		log_warnx("%s: polling not supported", a->name);
		goto out;
	} else if (op == FDMOP_FETCH && a->fetch->fetch == NULL) {
		log_warnx("%s: fetching not supported", a->name);
		goto out;
	}
	tim = get_time();

	/* start fetch */
	if (a->fetch->start != NULL) {
		if (a->fetch->start(a, &total) != FETCH_SUCCESS) {
			log_warnx("%s: start error. aborting", a->name);
			goto out;
		}
	}

	/* process fetch */
	log_debug2("%s: started processing", a->name);
	switch (op) {
	case FDMOP_POLL:
		error = poll_account(io, a);
		break;
	case FDMOP_FETCH:
		error = fetch_account(io, a, tim);
		break;
	default:
		fatalx("child: unexpected command");
	}
	log_debug2("%s: finished processing. exiting", a->name);

out:
	/* finish fetch */
	if (a->fetch->finish != NULL) {
		if (a->fetch->finish(a, error) != FETCH_SUCCESS)
			error = 1;
	}

	io->flags &= ~IO_NOWAIT;
	memset(&msg, 0, sizeof msg);

	msg.type = MSG_EXIT;
	log_debug3("%s: sending exit message to parent", a->name);
	if (privsep_send(io, &msg, NULL) != 0)
		fatalx("child: privsep_send error");
	log_debug3("%s: waiting for exit message from parent", a->name);
	if (privsep_recv(io, &msg, NULL) != 0)
		fatalx("child: privsep_recv error");
	if (msg.type != MSG_EXIT)
		fatalx("child: unexpected message");

#ifdef DEBUG
	COUNTFDS(a->name);
	xmalloc_report(a->name);
#endif 

	return (error);
}

int
poll_account(unused struct io *io, struct account *a)
{
	u_int	n;

	/* XXX use total? */
	log_debug2("%s: polling", a->name);
	
	if (a->fetch->poll(a, &n) == FETCH_ERROR) {
		log_warnx("%s: polling error. aborted", a->name);
		return (1);
	}

	log_info("%s: %u messages found", a->name, n);

	return (0);
}

int
fetch_poll(struct account *a, struct io *pio, struct mail_ctx *mctx,
    int blocked, u_int queued)
{
	static int	 holding;	/* holding fetch until queues drop */
	struct io	*rio, *iop[IO_POLLFDS];
	char		*cause;
	u_int		 n;
	int		 timeout, error;

	n = 1;
	iop[0] = pio;

	/*
	 * If the queue is empty and the fetch finished, must be all done.
	 */
	if (queued == 0 && mctx == NULL)
		return (FETCH_COMPLETE);

	/*
	 * Update the holding flag.
	 */
	if (queued >= (u_int) conf.queue_high)
		holding = 1;
	if (queued <= (u_int) conf.queue_low)
		holding = 0;

	/*
	 * If not finished, try to get a mail.
	 */
	if (mctx != NULL && !holding) {
		if ((error = a->fetch->fetch(a, mctx->mail)) != FETCH_AGAIN)
			return (error);
	}

	/*
	 * If the fetch itself not finished, fill in its io list.
	 */
	if (mctx != NULL && a->fetch->fill != NULL)
		a->fetch->fill(a, iop, &n);

	/*
	 * If that didn't add any fds, and we're not blocked for the parent
	 * then skip the poll entirely and tell the caller not to loop to
	 * us again immediately.
	 */
	if (n == 1 && !blocked)
		return (FETCH_NONE);

	/*
	 * If the queues are empty, or blocked waiting for the parent, then
	 * let poll block.
	 */
	timeout = 0;
	if (blocked || queued == 0)
		timeout = conf.timeout;

	log_debug3("%s: polling %u fds, timeout=%d", a->name, n, timeout);
	switch (io_polln(iop, n, &rio, timeout, &cause)) {
	case 0:
		if (rio == pio)
			fatalx("child: parent socket closed");
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (1);
	case -1:
		if (rio == pio)
			fatalx("child: parent socket error");
		if (errno == EAGAIN)
			break;
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	return (FETCH_AGAIN);
}

int
fetch_done(struct mail_ctx *mctx)
{
	struct account	*a = mctx->account;
	struct mail	*m = mctx->mail;

	if (a->fetch->done == NULL)
		return (0);

	if (conf.keep_all || a->keep)
		m->decision = DECISION_KEEP;
	switch (m->decision) {
	case DECISION_DROP:
		dropped++;
		log_debug("%s: deleting message %u", a->name, m->idx);
		break;
	case DECISION_KEEP:
		kept++;
		log_debug("%s: keeping message %u", a->name, m->idx);
		break;
	default:
		fatalx("invalid decision");
	}

	if (a->fetch->done(a, m) != FETCH_SUCCESS)
		return (1);

	return (0);
}

int
fetch_drain(void)
{
	struct mail_ctx	*mctx;

	while (!TAILQ_EMPTY(&doneq)) {
		mctx = TAILQ_FIRST(&doneq);
		if (fetch_done(mctx) != 0)
			return (1);

		TAILQ_REMOVE(&doneq, mctx, entry);
		fetch_free1(mctx);
	}

	return (0);
}

int
fetch_match(struct account *a, int *blocked, u_int *queued, struct msg *msg,
    struct msgbuf *msgbuf)
{
	struct mail_ctx	*mctx;

	if (TAILQ_EMPTY(&matchq))
		return (0);

	mctx = TAILQ_FIRST(&matchq);
	log_debug3("%s: trying (match) message %u", a->name, mctx->mail->idx);
	switch (mail_match(mctx, msg, msgbuf)) {
	case MAIL_ERROR:
		return (1);
	case MAIL_DELIVER:
		TAILQ_REMOVE(&matchq, mctx, entry);
		TAILQ_INSERT_TAIL(&deliverq, mctx, entry);
		break;
	case MAIL_DONE:
		TAILQ_REMOVE(&matchq, mctx, entry);
		TAILQ_INSERT_TAIL(&doneq, mctx, entry);
		(*queued)--;
		break;
	case MAIL_BLOCKED:
		*blocked = 1;
		break;
	}

	return (0);
}

int
fetch_deliver(struct account *a, int *blocked, struct msg *msg,
    struct msgbuf *msgbuf)
{
	struct mail_ctx	*mctx;

	if (TAILQ_EMPTY(&deliverq))
		return (0);

	mctx = TAILQ_FIRST(&deliverq);
	log_debug3("%s: trying (deliver) message %u", a->name, mctx->mail->idx);
	switch (mail_deliver(mctx, msg, msgbuf)) {
	case MAIL_ERROR:
		return (1);
	case MAIL_MATCH:
		TAILQ_REMOVE(&deliverq, mctx, entry);
		TAILQ_INSERT_TAIL(&matchq, mctx, entry);
		break;
	case MAIL_BLOCKED:
		*blocked = 1;
		break;
	}

	return (0);
}

int
fetch_flush(struct account *a, struct io *pio, u_int *queued)
{
	int	error;

	error = FETCH_AGAIN;
	while (error != FETCH_COMPLETE) {
		error = fetch_get(a, NULL, pio, queued);
		if (error == FETCH_ERROR)
			return (1);

		if (fetch_drain() != 0)
			return (1);
	}

	return (0);
}

int
fetch_get(struct account *a, struct mail_ctx *mctx, struct io *pio,
    u_int *queued)
{
	struct msg	 msg, *msgp;
	struct msgbuf	 msgbuf;
	int		 error, blocked;

	error = FETCH_AGAIN;
	msgp = NULL;
	while (error == FETCH_AGAIN) {
		blocked = 0;

		/*
		 * Match a mail.
		 */
		if (fetch_match(a, &blocked, queued, msgp, &msgbuf) != 0) {
			error = FETCH_ERROR;
			break;
		}

		/*
		 * Deliver a mail.
		 */
		if (fetch_deliver(a, &blocked, msgp, &msgbuf) != 0) {
			error = FETCH_ERROR;
			break;
		}

		/*
		 * Poll for new mails.
		 */
		log_debug3("%s: queued %u; blocked=%d", a->name, *queued,
		    blocked);
		error = fetch_poll(a, pio, mctx, blocked, *queued);
		if (error == FETCH_ERROR || error == FETCH_COMPLETE)
			break;

		/*
		 * Check for new privsep messages.
		 */
		msgp = NULL;
		if (!privsep_check(pio))
			continue;
		if (privsep_recv(pio, &msg, &msgbuf) != 0)
			fatalx("child: privsep_recv error");
		log_debug3("%s: got message type %d, id %u", a->name,
		    msg.type, msg.id);
		msgp = &msg;
	}

	return (error);
}

void
fetch_free1(struct mail_ctx *mctx)
{
	struct deliver_ctx	*dctx;

	while (!TAILQ_EMPTY(&mctx->dqueue)) {
		dctx = TAILQ_FIRST(&mctx->dqueue);
		TAILQ_REMOVE(&mctx->dqueue, dctx, entry);
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

	while (!TAILQ_EMPTY(&matchq)) {
		mctx = TAILQ_FIRST(&matchq);
		TAILQ_REMOVE(&matchq, mctx, entry);
		fetch_free1(mctx);
	}

	while (!TAILQ_EMPTY(&deliverq)) {
		mctx = TAILQ_FIRST(&deliverq);
		TAILQ_REMOVE(&deliverq, mctx, entry);
		fetch_free1(mctx);
	}

	while (!TAILQ_EMPTY(&doneq)) {
		mctx = TAILQ_FIRST(&doneq);
		TAILQ_REMOVE(&doneq, mctx, entry);
		fetch_free1(mctx);
	}
}

int
fetch_account(struct io *pio, struct account *a, double tim)
{
	struct mail	*m;
 	struct mail_ctx	*mctx;
	u_int	 	 n, queued;
	int		 error;

	log_debug2("%s: fetching", a->name);
	if (total != -1)
		log_debug("%s: %d messages found", a->name, total);

 	TAILQ_INIT(&matchq);
 	TAILQ_INIT(&deliverq);
 	TAILQ_INIT(&doneq);

	mctx = NULL;
	m = NULL;
	n = queued = dropped = kept = 0;
	for (;;) {
		/*
		 * If the last context was queued (mail received successfully),
		 * make a new one.
		 */
		if (mctx == NULL) {
			m = xcalloc(1, sizeof *m);
			m->body = -1;
			m->decision = DECISION_DROP;
			m->idx = ++a->idx;
			m->tim = get_time();

			mctx = xcalloc(1, sizeof *mctx);
			mctx->account = a;
			mctx->mail = m;
			mctx->msgid = 0;
			mctx->done = 0;

			mctx->matched = 0;

			mctx->account = a;
			mctx->io = pio;

			mctx->rule = TAILQ_FIRST(&conf.rules);
			TAILQ_INIT(&mctx->dqueue);
			ARRAY_INIT(&mctx->stack);
		}

		/*
		 * Try to get a mail.
		 */
		error = fetch_get(a, mctx, pio, &queued);
		if (error == FETCH_ERROR || error == FETCH_COMPLETE)
			goto out;

		/*
		 * Trim "From " line.
		 */
		if (error == FETCH_SUCCESS) {
			trim_from(m);
			if (m->size == 0)
				error = FETCH_EMPTY;
		}

		/*
		 * And handle the return code.
		 */
		switch (error) {
		case FETCH_EMPTY:
			log_warnx("%s: empty message", a->name);
			error = FETCH_ERROR;
			goto out;
		case FETCH_OVERSIZE:
			log_warnx("%s: message too big: %zu bytes (limit %zu)",
			    a->name, m->size, conf.max_size);
			if (conf.del_big) {
				/*
				 * Queue on the done queue and destroy the
				 * mail file.
				 */
				TAILQ_INSERT_TAIL(&doneq, mctx, entry);
				shm_destroy(&mctx->mail->shm);

				/*
				 * Set error to success to allocate a new
				 * context at the start of the loop.
				 */
				mctx = NULL;
				break;
			}
			error = FETCH_ERROR;
			goto out;
		case FETCH_SUCCESS:
			/*
			 * Got a mail: modify it and queue it.
			 */
			if (total != -1) {
				log_debug("%s: got message %u of %d in "
				    "%.3f seconds: size %zu, body %zd", a->name,
				    m->idx, total, get_time() - m->tim, m->size,
				    m->body);
			} else {
				log_debug("%s: got message %u in %.3f "
				    "seconds: size %zu, body %zd", a->name,
				    m->idx, get_time() - m->tim, m->size,
				    m->body);
			}
			fetch_transform(a, m);
			TAILQ_INSERT_TAIL(&matchq, mctx, entry);
			mctx = NULL;
			queued++;
			break;
		}

		/*
		 * Empty the done queue. Can get here either from FETCH_SUCCESS
		 * or FETCH_NONE.
		 */
		if (fetch_drain() != 0) {
			error = FETCH_ERROR;
			goto out;
		}

		/*
		 * Purge if necessary.
		 */
		if (conf.purge_after == 0 || a->fetch->purge == NULL)
			continue;

		n++;
		if (n >= conf.purge_after) {
			log_debug("%s: got %u mails, purging", a->name, n);
			n = 0;

			/*
			 * Must empty queues before purge to make sure things
			 * like POP3 indexing don't get ballsed up.
			 */
			if (fetch_flush(a, pio, &queued) != 0)
				break;
			if (a->fetch->purge(a) != FETCH_SUCCESS)
				break;
		}
	}

out:
	if (mctx != NULL) {
		mail_destroy(m);
		xfree(m);

		xfree(mctx);
	}

	/*
	 * Flush the queues if not an error.
	 */
	if (error != FETCH_ERROR) {
		if (fetch_flush(a, pio, &queued) != 0)
			error = FETCH_ERROR;
	}
	if (error != FETCH_ERROR) {
		if (fetch_drain() != 0)
			error = FETCH_ERROR;
	}

	/*
	 * Report error and free queues.
	 */
	if (error == FETCH_ERROR) {
		log_warnx("%s: fetching error. aborted", a->name);
		fetch_free();
	}

	tim = get_time() - tim;
	n = dropped + kept;
	if (n > 0) {
		log_info("%s: %u messages processed (%u kept) in %.3f seconds "
		    "(average %.3f)", a->name, n, kept, tim, tim / n);
		return (error == FETCH_ERROR);
	}

	log_info("%s: %u messages processed in %.3f seconds", a->name, n, tim);
	return (error == FETCH_ERROR);
}

int
fetch_transform(struct account *a, struct mail *m)
{
	char	*hdr, rtm[64], *rnm;
	u_int	 lines;
	size_t	 len;
	int	 error;

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
		if (rfc822_time(time(NULL), rtm, sizeof rtm) != NULL) {
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

	/* fill wrapped line list */
	lines = fill_wrapped(m);
	log_debug2("%s: found %u wrapped lines", a->name, lines);

	return (FETCH_SUCCESS);
}
