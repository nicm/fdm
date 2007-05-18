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

int	poll_account(struct account *, struct fetch_ctx *);
int	fetch_account(struct account *, struct fetch_ctx *, double);

int	fetch_match(struct account *, struct fetch_ctx *, struct msg *, 
	    struct msgbuf *);
int	fetch_deliver(struct account *, struct fetch_ctx *, struct msg *,
	    struct msgbuf *);
int	fetch_poll(struct account *, struct fetch_ctx *);
void	fetch_free(struct account *, struct fetch_ctx *);

double	time_polling = 0.0;
double	time_blocked = 0.0;

int
child_fetch(struct child *child, struct io *io)
{
	struct child_fetch_data	*data = child->data;
	enum fdmop 		 op = data->op;
	struct account 		*a = data->account;
	struct fetch_ctx	 fctx;
	struct msg	 	 msg;
	int			 error = 1;
	double			 tim;

#ifdef DEBUG
	xmalloc_clear();
	COUNTFDS(a->name);
#endif

	log_debug2("%s: fetch started, pid %ld", a->name, (long) getpid());

#ifndef NO_SETPROCTITLE
	setproctitle("child: %s", a->name);
#endif

	fill_info(NULL);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);
	tim = get_time();

	/* Start fetch. */
	if (a->fetch->connect != NULL) {
		if (a->fetch->connect(a) != 0) {
			log_warnx("%s: connect error. aborting", a->name);
			goto out;
		}
	}

	/* Initialise queues and counters. */ 
	memset(&fctx, 0, sizeof fctx);
	TAILQ_INIT(&fctx.matchq);
 	TAILQ_INIT(&fctx.deliverq);
 	TAILQ_INIT(&fctx.doneq);
	fctx.queued = fctx.dropped = fctx.kept = 0;
	fctx.io = io;

	/* Process fetch or poll. */
	log_debug2("%s: started processing", a->name);
	switch (op) {
	case FDMOP_POLL:
		error = poll_account(a, &fctx);
		break;
	case FDMOP_FETCH:
		error = fetch_account(a, &fctx, tim);
		break;
	default:
		fatalx("child: unexpected command");
	}
	log_debug2("%s: finished processing. exiting", a->name);

out:
	/* Finish fetch. */
	if (a->fetch->disconnect != NULL) {
		if (a->fetch->disconnect(a) != 0)
			error = 1;
	}

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
poll_account(struct account *a, struct fetch_ctx *fctx)
{
	struct io	*rio, *iop[IO_POLLFDS];
	char		*cause;
	u_int		 n;
	int		 timeout;

	if (a->fetch->poll == NULL) {
		log_warnx("%s: polling not supported", a->name);
		goto error;
	}

	log_debug2("%s: polling", a->name);

	for (;;) {
		if (a->fetch->closed != NULL && a->fetch->close != NULL) {
			if (a->fetch->closed(a))
				break;
			if (a->fetch->completed(a) && a->fetch->close(a) != 0)
				goto error;
		} else {
			if (a->fetch->completed(a))
				break;
		}

		timeout = 0;
		switch (a->fetch->poll(a, fctx)) {
		case FETCH_ERROR:
			goto error;
		case FETCH_BLOCK:
			timeout = conf.timeout;
			break;
		case FETCH_HOLD:
			continue;
		}

		n = 0;
		if (a->fetch->fill != NULL)
			a->fetch->fill(a, iop, &n);
		if (n == 0)
			continue;

		switch (io_polln(iop, n, &rio, timeout, &cause)) {
		case 0:
			log_warnx("%s: connection closed", a->name);
			goto error;
		case -1:
			if (errno == EAGAIN)
				break;
			log_warnx("%s: %s", a->name, cause);
			xfree(cause);
			goto error;
		}
	}
	
	log_info("%s: %u messages found", a->name, a->fetch->total(a));
	return (0);

error:
	log_warnx("%s: polling error. aborted", a->name);
	return (-1);
}

int
fetch_poll(struct account *a, struct fetch_ctx *fctx)
{
	struct io	*rio, *iop[IO_POLLFDS];
	char		*cause;
	u_int		 n;
	int		 timeout, error;
	double		 tim;

	n = 1;
	iop[0] = fctx->io;

	/*
	 * If the queues are empty and the fetch finished and closed, must be
	 * all done.
	 */
	if (fctx->queued == 0 && TAILQ_EMPTY(&fctx->doneq)) {
		/*
		 * If close/closed functions exist, call them after completion,
		 * otherwise just go by what the complete function says.
		 */
		if (a->fetch->closed != NULL && a->fetch->close != NULL) {
			if (a->fetch->closed(a))
				return (FETCH_COMPLETE);
			if (a->fetch->completed(a) && a->fetch->close(a) != 0)
				return (FETCH_ERROR);
		} else {
			if (a->fetch->completed(a))
				return (FETCH_COMPLETE);
		}
	}

	/*
	 * Update the holding flag.
	 */
	if (fctx->queued >= (u_int) conf.queue_high)
		fctx->holding = 1;
	if (fctx->queued <= (u_int) conf.queue_low)
		fctx->holding = 0;

	/*
	 * If not holding, try to get a mail.
	 */
	error = FETCH_HOLD;
	if (!fctx->holding && (error = a->fetch->fetch(a, fctx)) == FETCH_ERROR)
		return (error);

	/*
	 * If the fetch isn't holding for queue changes, fill in its io list.
	 */
	if (error != FETCH_HOLD && a->fetch->fill != NULL)
		a->fetch->fill(a, iop, &n);

	/*
	 * If that didn't add any fds and we're not blocked for the parent then
	 * skip the poll entirely and tell the caller not to loop to us again
	 * immediately.
	 */
	if (n == 1 && !fctx->blocked)
		return (FETCH_AGAIN);

	/*
	 * If the queues are empty, or blocked waiting for the parent, and
	 * the fetch lets us block, then let poll block.
	 */
	timeout = 0;
	if (error != FETCH_AGAIN && (fctx->blocked || fctx->queued == 0))
		timeout = conf.timeout;

	log_debug3("%s: polling %u fds, timeout=%d, error=%d",
	    a->name, n, timeout, error);
	tim = get_time();
	switch (io_polln(iop, n, &rio, timeout, &cause)) {
	case 0:
		if (rio == fctx->io)
			fatalx("child: parent socket closed");
		log_warnx("%s: connection closed", a->name);
		return (FETCH_ERROR);
	case -1:
		if (errno == EAGAIN)
			break;
		if (rio == fctx->io)
			fatalx("child: parent socket error");
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (FETCH_ERROR);
	}
	tim = get_time() - tim;

	time_polling += tim;
	if (fctx->blocked)
		time_blocked += tim;

	return (FETCH_AGAIN);
}

int
fetch_match(struct account *a, struct fetch_ctx *fctx, struct msg *msg, 
    struct msgbuf *msgbuf)
{
	struct mail_ctx	*mctx;

	if (TAILQ_EMPTY(&fctx->matchq))
		return (0);

	mctx = TAILQ_FIRST(&fctx->matchq);
	log_debug3("%s: trying (match) message %u", a->name, mctx->mail->idx);
	switch (mail_match(mctx, msg, msgbuf)) {
	case MAIL_ERROR:
		return (1);
	case MAIL_DELIVER:
		TAILQ_REMOVE(&fctx->matchq, mctx, entry);
		TAILQ_INSERT_TAIL(&fctx->deliverq, mctx, entry);
		break;
	case MAIL_DONE:
		TAILQ_REMOVE(&fctx->matchq, mctx, entry);
		TAILQ_INSERT_TAIL(&fctx->doneq, mctx, entry);
		fctx->queued--;
		break;
	case MAIL_BLOCKED:
		fctx->blocked = 1;
		break;
	}

	return (0);
}

int
fetch_deliver(struct account *a, struct fetch_ctx *fctx, struct msg *msg,
    struct msgbuf *msgbuf)
{
	struct mail_ctx	*mctx;

	if (TAILQ_EMPTY(&fctx->deliverq))
		return (0);

	mctx = TAILQ_FIRST(&fctx->deliverq);
	log_debug3("%s: trying (deliver) message %u", a->name, mctx->mail->idx);
	switch (mail_deliver(mctx, msg, msgbuf)) {
	case MAIL_ERROR:
		return (1);
	case MAIL_MATCH:
		TAILQ_REMOVE(&fctx->deliverq, mctx, entry);
		TAILQ_INSERT_TAIL(&fctx->matchq, mctx, entry);
		break;
	case MAIL_BLOCKED:
		fctx->blocked = 1;
		break;
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
		xfree(dctx);
	}

	ARRAY_FREE(&mctx->stack);
	mail_destroy(mctx->mail);
	xfree(mctx->mail);
	xfree(mctx);
}

void
fetch_free(unused struct account *a, struct fetch_ctx *fctx)
{
	struct mail_ctx	*mctx;

	while (!TAILQ_EMPTY(&fctx->matchq)) {
		mctx = TAILQ_FIRST(&fctx->matchq);
		TAILQ_REMOVE(&fctx->matchq, mctx, entry);
		fetch_free1(mctx);
	}

	while (!TAILQ_EMPTY(&fctx->deliverq)) {
		mctx = TAILQ_FIRST(&fctx->deliverq);
		TAILQ_REMOVE(&fctx->deliverq, mctx, entry);
		fetch_free1(mctx);
	}

	while (!TAILQ_EMPTY(&fctx->doneq)) {
		mctx = TAILQ_FIRST(&fctx->doneq);
		TAILQ_REMOVE(&fctx->doneq, mctx, entry);
		fetch_free1(mctx);
	}
}

int
fetch_account(struct account *a, struct fetch_ctx *fctx, double tim)
{
	struct msg	 msg, *msgp;
	struct msgbuf	 msgbuf;
	int		 error;
	u_int		 n, last;

	log_debug2("%s: fetching", a->name);

	last = 0;
	error = FETCH_AGAIN;
	while (error != FETCH_COMPLETE) {
		fctx->blocked = 0;

		/* Check for new privsep messages. */
		msgp = NULL;
		if (privsep_check(fctx->io)) {
			if (privsep_recv(fctx->io, &msg, &msgbuf) != 0)
				fatalx("child: privsep_recv error");
			log_debug3("%s: got message type %d, id %u", a->name,
			    msg.type, msg.id);
			msgp = &msg;
		}

		/* Match a mail. */
		if (fetch_match(a, fctx, msgp, &msgbuf) != 0) {
			error = FETCH_ERROR;
			break;
		}
		
		/* Deliver a mail. */
		if (fetch_deliver(a, fctx, msgp, &msgbuf) != 0) {
			error = FETCH_ERROR;
			break;
		}
			
		/* Poll for new mails or privsep messages. */
		log_debug3("%s: queued %u; blocked=%d", a->name, fctx->queued,
		    fctx->blocked);
		if ((error = fetch_poll(a, fctx)) == FETCH_ERROR)
			break;
			
		/* Purge if necessary. */
		if (conf.purge_after == 0 || a->fetch->purge == NULL)
			continue;

		n = fctx->dropped + fctx->kept;
		if (n != last && n % conf.purge_after == 0) {
			last = n;

			log_debug("%s: purging after %u mails", a->name, n);
			if (a->fetch->purge(a) != 0) {
				error = FETCH_ERROR;
				break;
			}
		}
	}

	/* Report error and free queues. */
	if (error == FETCH_ERROR) {
		log_warnx("%s: fetching error. aborted", a->name);
		fetch_free(a, fctx);
	}

	tim = get_time() - tim;
	n = fctx->dropped + fctx->kept;
	if (n > 0) {
		log_info("%s: %u messages processed (%u kept) in %.3f seconds "
		    "(average %.3f)", a->name, n, fctx->kept, tim, tim / n);
		log_debug("%s: polled for %.3f seconds (%.3f blocked)",
		    a->name, time_polling, time_blocked);
		return (error == FETCH_ERROR);
	}

	log_info("%s: %u messages processed in %.3f seconds", a->name, n, tim);
	return (error == FETCH_ERROR);
}
