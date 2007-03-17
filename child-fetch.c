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

int	fetch_flush(struct account *, struct io *, int *, int *, int *, 
	    const char **);
int	fetch_poll(struct account *a, int, struct io *, struct io **);
int	fetch_transform(struct account *, struct mail *);
int	fetch_rule(struct match_ctx *, const char **);

int	run_match(struct account *, const char **);
int	run_deliver(struct account *, struct io *, int *, const char **);
int	run_done(struct account *, int *, int *, const char **);

void	flush_queue(struct match_queue *);
u_int	queue_length(struct match_queue *);

struct strings *get_users(struct match_ctx *, struct rule *, struct action *,
    int *);

int	do_expr(struct rule *, struct match_ctx *);
int	do_deliver(struct rule *, struct match_ctx *);
int	do_rules(struct match_ctx *, struct rules *, const char **);

int	start_action(struct io *, struct deliver_ctx *);
int	finish_action(struct deliver_ctx *, struct msg *, void *, size_t);

/* XXX wrap in struct (match_state?) and pass, with kept/dropped etc */
struct match_queue	 matchq;
struct match_queue	 deliverq;
struct match_queue	 doneq;

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
	log_debug2("%s: started, pid %ld", a->name, (long) getpid());

#ifndef NO_SETPROCTITLE
	setproctitle("child: %s", a->name);
#endif

	fill_info(NULL);
	log_debug2("%s: user is: %s, home is: %s", a->name, conf.info.user,
	    conf.info.home);

	if (op == FDMOP_POLL && a->fetch->poll == NULL) {
		log_info("%s: polling not supported", a->name);
		goto out;
	} else if (op == FDMOP_FETCH && a->fetch->fetch == NULL) {
		log_info("%s: fetching not supported", a->name);
		goto out;
	}
	tim = get_time();

	/* start fetch */
	if (a->fetch->start != NULL && a->fetch->start(a) != FETCH_SUCCESS) {
		log_warnx("%s: start error. aborting", a->name);
		goto out;
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
	if (a->fetch->finish != NULL && a->fetch->finish(a) != FETCH_SUCCESS)
		error = 1;

	io->flags &= ~IO_NOWAIT;
	memset(&msg, 0, sizeof msg);

	msg.type = MSG_EXIT;
	log_debug3("%s: sending exit message to parent", a->name);
	if (privsep_send(io, &msg, NULL, 0) != 0)
		fatalx("child: privsep_send error");
	log_debug3("%s: waiting for exit message from parent", a->name);
	if (privsep_recv(io, &msg, NULL, 0) != 0)
		fatalx("child: privsep_recv error");
	if (msg.type != MSG_EXIT)
		fatalx("child: unexpected message");

	io_close(io);
	io_free(io);

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

	log_debug2("%s: polling", a->name);

	if (a->fetch->poll(a, &n) == FETCH_ERROR) {
		log_warnx("%s: polling error. aborted", a->name);
		return (1);
	}

	log_info("%s: %u messages found", a->name, n);

	return (0);
}

int
run_match(struct account *a, const char **cause)
{
	struct match_ctx	*mctx;

	if (TAILQ_EMPTY(&matchq))
		return (0);

	mctx = TAILQ_FIRST(&matchq);
	log_debug3("%s: running match queue", a->name);

	switch (fetch_rule(mctx, cause)) {
	case FETCH_ERROR:
		return (1);
	case FETCH_AGAIN:
		/* delivering mail, queue for delivery */
		log_debug3("%s: adding to deliver queue", a->name);
		TAILQ_REMOVE(&matchq, mctx, entry);
		TAILQ_INSERT_TAIL(&deliverq, mctx, entry);
		break;
	case FETCH_COMPLETE:
		/* finished with mail, queue on done queue */
		log_debug3("%s: adding to done queue", a->name);
		TAILQ_REMOVE(&matchq, mctx, entry);
		TAILQ_INSERT_TAIL(&doneq, mctx, entry);

		/*
		 * Destroy mail data now it is finished, just keep the mail
		 * structure.
		 */
		shm_destroy(&mctx->mail->shm);
		break;
	}

	return (0);
}

int
run_deliver(struct account *a, struct io *io, int *blocked, const char **cause)
{
	struct match_ctx	*mctx;
	struct deliver_ctx	*dctx;
	struct msg		 msg;
	void			*buf;
	size_t			 len;

	*blocked = 0;
	if (TAILQ_EMPTY(&deliverq))
		return (0);

	mctx = TAILQ_FIRST(&deliverq);
	if (TAILQ_EMPTY(&mctx->dqueue)) {
		/* delivery done. return to match queue */
		log_debug3("%s: returning to match queue", a->name);
		TAILQ_REMOVE(&deliverq, mctx, entry);
		TAILQ_INSERT_HEAD(&matchq, mctx, entry);
		return (0);
	}

	/* start the first action */
	log_debug3("%s: running deliver queue", a->name);
	dctx = TAILQ_FIRST(&mctx->dqueue);

	if (dctx->blocked) {
		/* check for reply from parent and finish */
		if (!privsep_check(io)) {
			*blocked = 1;
			return (0);
		}

		if (privsep_recv(io, &msg, &buf, &len) != 0)
			fatalx("child: privsep_recv error");
		if (msg.type != MSG_DONE)
			fatalx("child: unexpected message");
		
		if (finish_action(dctx, &msg, buf, len) != 0) {
			*cause = "delivery";
			return (1);
		}

		goto remove;
	}

	if (start_action(mctx->io, dctx) != 0) {
		*cause = "delivery";
		return (1);
	}
	if (dctx->blocked) {
		*blocked = 1;
		return (0);
	}

remove:
	TAILQ_REMOVE(&mctx->dqueue, dctx, entry);
	log_debug("%s: message %u delivered (rule %u, %s) after %.3f seconds", 
	    a->name, mctx->mail->idx, dctx->rule->idx, 
	    dctx->action->deliver->name,  get_time() - dctx->tim);
	xfree(dctx);
	return (0);
}

int
run_done(struct account *a, int *dropped, int *kept, const char **cause)
{
	struct match_ctx	*mctx;
	struct mail		*m;
	int			 error = 0;
	const char		*type;

	if (TAILQ_EMPTY(&doneq))
		return (0);
	
	mctx = TAILQ_FIRST(&doneq);
	m = mctx->mail;
	log_debug3("%s: running done queue", a->name);

	TAILQ_REMOVE(&doneq, mctx, entry);
	ARRAY_FREE(&mctx->stack);
	log_debug("%s: message %u done after %.3f seconds", a->name, m->idx,
	    get_time() - mctx->tim);
	xfree(mctx);

	if (a->fetch->done != NULL) {
		switch (m->decision) {
		case DECISION_DROP:
			type = "deleting";
			(*dropped)++;
			break;
		case DECISION_KEEP:
			type = "keeping";
			(*kept)++;
			break;
		default:
			fatalx("invalid decision");
		}
		log_debug("%s: %s message %u", a->name, type, m->idx);

		if (a->fetch->done(a, m) != FETCH_SUCCESS) {
			*cause = type;
			error = 1;
		}
	}

	mail_destroy(m);
	xfree(m);

	return (error);
}

void
flush_queue(struct match_queue *mq)
{
	struct match_ctx	*mctx;
	struct mail		*m;

	while (!TAILQ_EMPTY(mq)) {
		mctx = TAILQ_FIRST(mq);
		m = mctx->mail;

		TAILQ_REMOVE(mq, mctx, entry);
		ARRAY_FREE(&mctx->stack);
		xfree(mctx);

		mail_destroy(m);
		xfree(m);
	}
}

u_int
queue_length(struct match_queue *mq)
{
	struct match_ctx	*mctx;
	u_int			 n;

	n = 0;
	TAILQ_FOREACH(mctx, mq, entry)
	        n++;

	return (n);
}

int
fetch_poll(struct account *a, int blocked, struct io *pio, struct io **rio)
{
	int	 	 timeout;
	char		*cause;
	struct io	*iop[NFDS];
	u_int		 n;

	n = 1;
	iop[0] = pio;

	if (a->fetch->fill != NULL)
		a->fetch->fill(a, iop, &n);
	if (n == 1 && !blocked)
		return (0); 
	
	timeout = 0;
	if (TAILQ_EMPTY(&matchq) && (TAILQ_EMPTY(&deliverq) || blocked))
		timeout = conf.timeout;

	log_debug3("%s: polling %u fds, timeout=%d", a->name, n, timeout);
	switch (io_polln(iop, n, rio, timeout, &cause)) {
	case 0:
		log_warnx("%s: connection unexpectedly closed", a->name);
		return (1);
	case -1:
		if (errno == EAGAIN)
			return (0);
		log_warnx("%s: %s", a->name, cause);
		xfree(cause);
		return (1);
	}

	return (0);
}

int
fetch_flush(struct account *a, struct io *pio, int *blocked, int *dropped,
    int *kept, const char **cause)
{
	while (!TAILQ_EMPTY(&matchq) || !TAILQ_EMPTY(&deliverq)) {
		if (run_match(a, cause) != 0)
			return (1);
		if (run_deliver(a, pio, blocked, cause) != 0)
			return (1);

		if (!TAILQ_EMPTY(&deliverq) && *blocked) {
			pio->flags &= ~IO_NOWAIT;
			if (!TAILQ_EMPTY(&matchq))
				pio->flags |= IO_NOWAIT;
			switch (io_poll(pio, NULL)) {
			case 0:
				fatalx("child: parent socket closed");
			case -1:
				if (errno == EAGAIN)
					break;
				fatalx("child: parent socket error");
			}
		}

		if (run_done(a, dropped, kept, cause) != 0)
			return (1);
	}

	while (!TAILQ_EMPTY(&doneq)) {
		if (run_done(a, dropped, kept, cause) != 0)
			return (1);
	}

	return (0);
}

int
fetch_account(struct io *pio, struct account *a, double tim)
{
	struct mail	 	*m;
	u_int	 	 	 n, dropped, kept, total;
	int		 	 error, blocked, holding;
 	const char		*cause = NULL;
	struct match_ctx	*mctx;
	struct io		*rio;

	log_debug2("%s: fetching", a->name);

	TAILQ_INIT(&matchq);
	TAILQ_INIT(&deliverq);
	TAILQ_INIT(&doneq);

	n = dropped = kept = 0;
	m = NULL;
	blocked = 0; 
	for (;;) {
		m = xcalloc(1, sizeof *m);
		m->body = -1;
		m->decision = DECISION_DROP;
		m->done = 0;
		m->idx = ++a->idx;
		m->tim = get_time();

		/* fetch a message */
		error = FETCH_AGAIN;
		rio = NULL;
		holding = 0;
		while (error == FETCH_AGAIN) {
			total = queue_length(&matchq) + queue_length(&deliverq);
			if (total >= MAXMAILQUEUED)
				holding = 1;
			if (total < MINMAILQUEUED)
				holding = 0;

			log_debug3("%s: queue %u; blocked=%d; holding=%d",
			    a->name, total, blocked, holding);

			if (!holding) {
				if (rio != pio) {
					error = a->fetch->fetch(a, m);
					switch (error) {
					case FETCH_ERROR:
						if (rio != pio) {
							cause = "fetching";
							goto out;
						}
						fatalx("child: lost parent");
					case FETCH_COMPLETE:
						goto out;
					}
				}
			}
			if (error == FETCH_AGAIN) {
				if (fetch_poll(a, blocked, pio,&rio) != 0)
					goto out;
			}

			if (run_match(a, &cause) != 0)
				goto out;
			if (run_deliver(a, pio, &blocked, &cause) != 0)
				goto out;
		}

		log_debug("%s: message %u fetched after %.3f seconds", a->name,
		    m->idx, get_time() - m->tim);
		
		if (error != FETCH_OVERSIZE && error != FETCH_EMPTY) {
			trim_from(m);
			if (m->size == 0)
				error = FETCH_EMPTY;
		}

		switch (error) {
		case FETCH_EMPTY:
			log_warnx("%s: empty message", a->name);
			cause = "fetching";
			goto out;
		case FETCH_OVERSIZE:
			log_warnx("%s: message too big: %zu bytes (limit %zu)",
			    a->name, m->size, conf.max_size);
			if (conf.del_big)
				break;
			cause = "fetching";
			goto out;
		}

		log_debug("%s: got message %u: size %zu, body %zd", a->name,
		    m->idx, m->size, m->body);
		fetch_transform(a, m);

		/* construct mctx */
		mctx = xcalloc(1, sizeof *mctx);
		mctx->tim = get_time();
		mctx->io = pio;
		mctx->account = a;
		mctx->mail = m;
		ARRAY_INIT(&mctx->stack);
		mctx->rule = TAILQ_FIRST(&conf.rules);
		mctx->matched = mctx->stopped = 0;
		TAILQ_INIT(&mctx->dqueue);
		m = NULL; /* clear m to avoid double-free if out later */

		/* and queue it */
		log_debug3("%s: adding to match queue", a->name);
		TAILQ_INSERT_TAIL(&matchq, mctx, entry);

		/* finish up a done mail */
		if (run_done(a, &dropped, &kept, &cause) != 0)
			goto out;
		if (queue_length(&doneq) > MAXMAILQUEUED) {
			while (queue_length(&doneq) > MINMAILQUEUED) {
				if (run_done(a, &dropped, &kept, &cause) != 0)
					goto out;
			}
		}

		if (conf.purge_after == 0 || a->fetch->purge == NULL)
			continue;

		n++;
		if (n >= conf.purge_after) {
			log_debug("%s: got %u mails, purging", a->name, n);
			
			/*
			 * Must empty queues before purge to make sure things
			 * like POP3 indexing don't get ballsed up.
			 */
			if (fetch_flush(a, pio, &blocked, &dropped, &kept,
			    &cause) != 0)
				goto out;

			if (a->fetch->purge(a) != FETCH_SUCCESS) {
				cause = "purging";
				goto out;
			}

			n = 0;
		}
	}

out:
	if (m != NULL) {
		mail_destroy(m);
		xfree(m);
	}

	if (cause == NULL)
		fetch_flush(a, pio, &blocked, &dropped, &kept, &cause);
	if (cause != NULL) {
		flush_queue(&matchq);
		flush_queue(&deliverq);
		flush_queue(&doneq);

		log_warnx("%s: %s error. aborted", a->name, cause);
	}
	
	tim = get_time() - tim;
	n = dropped + kept;
	if (n > 0) {
		log_info("%s: %u messages processed (%u kept) in %.3f seconds "
		    "(average %.3f)", a->name, n, kept, tim, tim / n);
	} else {
	        log_info("%s: %u messages processed in %.3f seconds",
		    a->name, n, tim);
	}

	return (cause != NULL);
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

int
fetch_rule(struct match_ctx *mctx, const char **cause)
{
	struct account		*a = mctx->account;
	struct strings		*aa;
	struct mail		*m = mctx->mail;
	struct rule		*r = mctx->rule;
	u_int		 	 i;
	int		 	 error;
	char			*tkey, *tvalue;

	/* matching finished */
	if (m->done) {
		if (conf.keep_all || a->keep)
			m->decision = DECISION_KEEP;
		return (FETCH_COMPLETE);
	}

	/* end of ruleset reached */
	if (r == NULL) {
		switch (conf.impl_act) {
		case DECISION_NONE:
			log_warnx("%s: reached end of ruleset. no "
			    "unmatched-mail option; keeping mail",  a->name);
			m->decision = DECISION_KEEP;
			break;
		case DECISION_KEEP:
			log_debug2("%s: reached end of ruleset. keeping mail",
			    a->name);
			m->decision = DECISION_KEEP;
			break;
		case DECISION_DROP:
			log_debug2("%s: reached end of ruleset. dropping mail",
			    a->name);
			m->decision = DECISION_DROP;
			break;
		}
		m->done = 1;
		return (FETCH_SUCCESS);
	}

	mctx->rule = TAILQ_NEXT(mctx->rule, entry);
	while (mctx->rule == NULL) {
		if (ARRAY_EMPTY(&mctx->stack))
			break;
		mctx->rule = ARRAY_LAST(&mctx->stack, struct rule *);
		mctx->rule = TAILQ_NEXT(mctx->rule, entry);
		ARRAY_TRUNC(&mctx->stack, 1, struct rule *);
	}

	aa = r->accounts;
	if (!ARRAY_EMPTY(aa)) {
		for (i = 0; i < ARRAY_LENGTH(aa); i++) {
			if (name_match(ARRAY_ITEM(aa, i, char *), a->name))
				break;
		}
		if (i == ARRAY_LENGTH(aa))
			return (FETCH_SUCCESS);
	}

	/* match all the regexps */
	switch (r->type) {
	case RULE_EXPRESSION:
		/* combine wrapped lines */
		set_wrapped(m, ' ');
		
		/* perform the expression */
		if ((error = do_expr(r, mctx)) == -1) {
			*cause = "matching";
			return (FETCH_ERROR);
		}
		
		/* continue if no match */
		if (!error)
			return (FETCH_SUCCESS);
		break;
	case RULE_ALL:
		break;
	}

	/* reset wrapped lines */
	set_wrapped(m, '\n');
		
	/* report rule number */
	if (TAILQ_EMPTY(&r->rules))
		log_debug2("%s: matched to rule %u", a->name, r->idx);
	else
		log_debug2("%s: matched to rule %u (nested)", a->name, r->idx);

	/* deal with nested rules */
	if (!TAILQ_EMPTY(&r->rules)) {
		log_debug2("%s: entering nested rules", a->name);
		ARRAY_ADD(&mctx->stack, r, struct rule *);
		mctx->rule = TAILQ_FIRST(&r->rules);
		return (FETCH_SUCCESS);
	}
	
	/* tag mail if needed */
	if (r->key.str != NULL) {
		tkey = replacestr(&r->key, m->tags, m, &m->rml);
		tvalue = replacestr(&r->value, m->tags, m, &m->rml);
		
		if (tkey != NULL && *tkey != '\0' && tvalue != NULL) {
			log_debug2("%s: tagging message: %s (%s)", 
			    a->name, tkey, tvalue);
			add_tag(&m->tags, tkey, "%s", tvalue);
		}
		
		if (tkey != NULL)
			xfree(tkey);
		if (tvalue != NULL)
			xfree(tvalue);
	}

	/* if this rule is marked as stop, mark the mail as done */
	if (r->stop)
		m->done = 1;

	/* handle delivery */
	if (r->actions != NULL) {
		log_debug2("%s: delivering message", a->name);
		mctx->matched = 1;
		if (do_deliver(r, mctx) != 0) {
			*cause = "delivery";
			return (FETCH_ERROR);
		}
		return (FETCH_AGAIN);
	}

	return (FETCH_SUCCESS);
}

int
do_expr(struct rule *r, struct match_ctx *mctx)
{
	int		 fres, cres;
	struct expritem	*ei;
	char		 desc[DESCBUFSIZE];

	fres = 0;
	TAILQ_FOREACH(ei, r->expr, entry) {
		cres = ei->match->match(mctx, ei);
		if (cres == MATCH_ERROR)
			return (-1);
		cres = cres == MATCH_TRUE;
		if (ei->inverted)
			cres = !cres;
		switch (ei->op) {
		case OP_NONE:
		case OP_OR:
			fres = fres || cres;
			break;
		case OP_AND:
			fres = fres && cres;
			break;
		}

		ei->match->desc(ei, desc, sizeof desc);
		log_debug2("%s: tried %s%s, got %d", mctx->account->name,
		    ei->inverted ? "not " : "", desc, cres);
	}

	return (fres);
}

int
do_deliver(struct rule *r, struct match_ctx *mctx)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct action		*t;
	struct actions		*ta;
	u_int		 	 i, j, k;
	char			*s;
	struct replstr		*rs;
	struct deliver_ctx	*dctx;
	struct strings		*users;
	int			 should_free;

	for (i = 0; i < ARRAY_LENGTH(r->actions); i++) {
		rs = &ARRAY_ITEM(r->actions, i, struct replstr);
		s = replacestr(rs, m->tags, m, &m->rml);

		log_debug2("%s: looking for actions matching: %s", a->name, s);
		ta = match_actions(s);
		if (ARRAY_EMPTY(ta))
			goto empty;
		xfree(s);

		log_debug2("%s: found %u actions", a->name, ARRAY_LENGTH(ta));
		for (j = 0; j < ARRAY_LENGTH(ta); j++) {
			t = ARRAY_ITEM(ta, j, struct action *);
			users = get_users(mctx, r, t, &should_free);

			for (k = 0; k < ARRAY_LENGTH(users); k++) {
				dctx = xmalloc(sizeof *dctx);
				dctx->action = t;
				dctx->account = a;
				dctx->rule = r;
				dctx->mail = m;
				dctx->uid = ARRAY_ITEM(users, k, uid_t);
				dctx->blocked = 0;

				TAILQ_INSERT_TAIL(&mctx->dqueue, dctx, entry);
			}

			if (should_free)
				ARRAY_FREEALL(users);
		}

		ARRAY_FREEALL(ta);
	}

	return (0);

empty:
	xfree(s);
	ARRAY_FREEALL(ta);
	log_warnx("%s: no actions matching: %s (%s)", a->name, s, rs->str);
	return (1);
}

struct strings *
get_users(struct match_ctx *mctx, struct rule *r, struct action *t,
    int *should_free)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct strings		*users;

	*should_free = 0;
	users = NULL;
	if (r->find_uid) {		/* rule comes first */
		*should_free = 1;
		users = find_users(m);
	} else if (r->users != NULL) {
		*should_free = 0;
		users = r->users;
	} else if (t->find_uid) {	/* then action */
		*should_free = 1;
		users = find_users(m);
	} else if (t->users != NULL) {
		*should_free = 0;
		users = t->users;
	} else if (a->find_uid) {	/* then account */
		*should_free = 1;
		users = find_users(m);
	} else if (a->users != NULL) {
		*should_free = 0;
		users = a->users;
	}
	if (users == NULL) {
		*should_free = 1;
		users = xmalloc(sizeof *users);
		ARRAY_INIT(users);
		ARRAY_ADD(users, conf.def_user, uid_t);
	}

	return (users);
}

int
start_action(struct io *io, struct deliver_ctx *dctx)
{
	struct account	*a = dctx->account;
	struct action	*t = dctx->action;
	struct mail	*m = dctx->mail;
	struct mail	*md = &dctx->wr_mail;
	struct msg	 msg;
	u_int		 lines;	

	dctx->tim = get_time();
 	if (t->deliver->deliver == NULL)
		return (0);

	log_debug2("%s: running action %s as user %lu", a->name, t->name,
	    (u_long) dctx->uid);
	add_tag(&m->tags, "action", "%s", t->name);

	/* just deliver now for in-child delivery */
	if (t->deliver->type == DELIVER_INCHILD) {
		dctx->blocked = 0;
		if (t->deliver->deliver(dctx, t) != DELIVER_SUCCESS)
			return (1);
		return (0);
	}

	/* if the current user is the same as the deliver user, don't bother
	   passing up either */
#ifndef ALWAYSPARENT
	if (t->deliver->type == DELIVER_ASUSER && dctx->uid == geteuid()) {
		dctx->blocked = 0;
		if (t->deliver->deliver(dctx, t) != DELIVER_SUCCESS)
			return (1);
		return (0);
	}
	if (t->deliver->type == DELIVER_WRBACK && dctx->uid == geteuid()) {
		dctx->blocked = 0;

		mail_open(md, IO_BLOCKSIZE);
		md->decision = m->decision;
		
		if (t->deliver->deliver(dctx, t) != DELIVER_SUCCESS) {
			mail_destroy(md);
			return (1);
		}

		memcpy(&msg.data.mail, md, sizeof msg.data.mail);
		cleanup_deregister(md->shm.name);

		mail_receive(m, &msg);
		log_debug2("%s: received modified mail: size %zu, body %zd",
		    a->name, m->size, m->body);

		/* trim from line */
		trim_from(m);
	
		/* and recreate the wrapped array */
		lines = fill_wrapped(m);
		log_debug2("%s: found %u wrapped lines", a->name, lines);
		
		return (0);
	}
#endif

	memset(&msg, 0, sizeof msg);
	msg.type = MSG_ACTION;

	msg.data.account = a;
	msg.data.action = t;
	msg.data.uid = dctx->uid;

	mail_send(m, &msg);

	log_debug3("%s: sending action to parent", a->name);
	if (privsep_send(io, &msg, m->tags, STRB_SIZE(m->tags)) != 0) 
		fatalx("child: privsep_send error");
	dctx->blocked = 1;

	return (0);
}

int
finish_action(struct deliver_ctx *dctx, struct msg *msg, void *buf, size_t len)
{	
	struct account	*a = dctx->account;
	struct action	*t = dctx->action;
	struct mail	*m = dctx->mail;
	u_int		 lines;
	
	if (buf == NULL || len == 0)
		fatalx("child: bad tags");
	strb_destroy(&m->tags);
	m->tags = buf;
	update_tags(&m->tags);
	
	if (msg->data.error != 0)
		return (1);
	
	if (t->deliver->type != DELIVER_WRBACK)
		return (0);

	mail_receive(m, msg);
	log_debug2("%s: received modified mail: size %zu, body %zd", a->name,
	    m->size, m->body);

	/* trim from line */
	trim_from(m);
	
	/* and recreate the wrapped array */
	lines = fill_wrapped(m);
	log_debug2("%s: found %u wrapped lines", a->name, lines);

	return (0);
}
