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
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"
#include "match.h"

void		apply_result(struct expritem *, int *, int);

struct users   *find_delivery_users(struct mail_ctx *, struct action *, int *);
int		fill_delivery_queue(struct mail_ctx *, struct rule *);
void		fill_delivery_action(struct mail_ctx *, struct rule *,
    		    struct action *, struct users *);

int		start_action(struct mail_ctx *, struct deliver_ctx *);
int		finish_action(struct deliver_ctx *, struct msg *,
		    struct msgbuf *);

#define ACTION_DONE 0
#define ACTION_ERROR 1
#define ACTION_PARENT 2

int
mail_match(struct mail_ctx *mctx, struct msg *msg, struct msgbuf *msgbuf)
{
	struct account	*a = mctx->account;
	struct mail	*m = mctx->mail;
	struct strings	*aa;
	struct expritem	*ei;
	struct users	*users;
	u_int		 i;
	int		 should_free, this, error = MAIL_CONTINUE;
	char		*an, desc[DESCBUFSIZE];

	set_wrapped(m, ' ');

	/*
	 * If blocked, check for msgs from parent.
	 */
	if (mctx->msgid != 0) {
		if (msg == NULL || msg->id != mctx->msgid)
			return (MAIL_BLOCKED);
		mctx->msgid = 0;

		if (msg->type != MSG_DONE)
			fatalx("child: unexpected message");
		if (msgbuf->buf != NULL && msgbuf->len != 0) {
			strb_destroy(&m->tags);
			m->tags = msgbuf->buf;
			update_tags(&m->tags);
		}

		ei = mctx->expritem;
		switch (msg->data.error) {
		case MATCH_ERROR:
			return (MAIL_ERROR);
		case MATCH_TRUE:
			this = 1; 
			break;
		case MATCH_FALSE:
			this = 0;
			break;
		default:
			fatalx("child: unexpected response");
		}
		apply_result(ei, &mctx->result, this);
	
		goto next_expritem;
	}

	/*
	 * Check for completion and end of ruleset.
	 */
	if (mctx->done)
		return (MAIL_DONE);
	if (mctx->rule == NULL) {
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
		return (MAIL_DONE);
	}

	/*
	 * Expression not started. Start it.
	 */
	if (mctx->expritem == NULL) {
		/*
		 * Check rule account list.
		 */
		aa = mctx->rule->accounts;
		if (aa != NULL && !ARRAY_EMPTY(aa)) {
			for (i = 0; i < ARRAY_LENGTH(aa); i++) {
				an = ARRAY_ITEM(aa, i, char *);
				if (name_match(an, a->name))
					break;
			}
			if (i == ARRAY_LENGTH(aa)) {
				mctx->result = 0;
				goto skip;
			}
		}

		/*
		 * No expression. Must be an "all" rule, treat it as always
		 * true.
		 */
		if (mctx->rule->expr == NULL || TAILQ_EMPTY(mctx->rule->expr)) {
			mctx->result = 1;
			goto skip;
		}

		/*
		 * Start the expression.
		 */
		mctx->result = 0;
		mctx->expritem = TAILQ_FIRST(mctx->rule->expr);
	}

	/*
	 * Check this expression item and adjust the result.
	 */
	ei = mctx->expritem;

	/* Handle short-circuit evaluation. */
	switch (ei->op) {
	case OP_NONE:
		break;
	case OP_AND:
		/* And and the result is already false. */
		if (!mctx->result)
			goto next_expritem;
		break;
	case OP_OR:
		/* Or and the result is already true. */
		if (mctx->result)
			goto next_expritem;
		break;
	}

	switch (ei->match->match(mctx, ei)) {
	case MATCH_ERROR:
		return (MAIL_ERROR);
	case MATCH_PARENT:
		return (MAIL_BLOCKED);
	case MATCH_TRUE:
		this = 1; 
		break;
	case MATCH_FALSE:
		this = 0;
		break;
	default:
		fatalx("child: unexpected op");
	}
	apply_result(ei, &mctx->result, this);

	ei->match->desc(ei, desc, sizeof desc);
	log_debug3("%s: tried %s, result now %d", a->name, desc, mctx->result);

next_expritem:
	/*
	 * Move to the next item. If there is one, then return.
	 */
	mctx->expritem = TAILQ_NEXT(mctx->expritem, entry);
	if (mctx->expritem != NULL)
		return (MAIL_CONTINUE);

skip:
	log_debug3("%s: finished rule %u, result %d", a->name, mctx->rule->idx,
	    mctx->result);

	/*
	 * If the result was false, skip to find the next rule.
	 */
	if (!mctx->result)
		goto next_rule;
	mctx->matched = 1;
	log_debug2("%s: matched to rule %u", a->name, mctx->rule->idx);

	/*
	 * If this rule is stop, mark the context so when we get back after
	 * delivery we know to stop.
	 */
	if (mctx->rule->stop)
		mctx->done = 1;

	/*
	 * Handle nested rules.
	 */
	if (!TAILQ_EMPTY(&mctx->rule->rules)) {
		log_debug2("%s: entering nested rules", a->name);

		/*
		 * Stack the current rule (we are at the end of it so the
		 * the expritem must be NULL already).
		 */
		ARRAY_ADD(&mctx->stack, mctx->rule, struct rule *);

		/*
		 * Continue with the first rule of the nested list.
		 */
		mctx->rule = TAILQ_FIRST(&mctx->rule->rules);
		return (MAIL_CONTINUE);
	}

	/* 
	 * Handle lambda actions.
	 */
	if (mctx->rule->lambda != NULL) {
		users = find_delivery_users(mctx, NULL, &should_free);

		fill_delivery_action(mctx, 
		    mctx->rule, mctx->rule->lambda, users);
			
		if (should_free)
			ARRAY_FREEALL(users);
		error = MAIL_DELIVER;
	}

	/*
	 * Fill the delivery action queue.
	 */
	if (!ARRAY_EMPTY(mctx->rule->actions)) {
		if (fill_delivery_queue(mctx, mctx->rule) != 0)
			return (MAIL_ERROR);
		error = MAIL_DELIVER;
	}

next_rule:
	/*
	 * Move to the next rule.
	 */
	mctx->rule = TAILQ_NEXT(mctx->rule, entry);

	/*
	 * If no more rules, try to move up the stack.
	 */
	while (mctx->rule == NULL) {
		if (ARRAY_EMPTY(&mctx->stack))
			break;
		log_debug2("%s: exiting nested rules", a->name);
		mctx->rule = ARRAY_LAST(&mctx->stack, struct rule *);
		mctx->rule = TAILQ_NEXT(mctx->rule, entry);
		ARRAY_TRUNC(&mctx->stack, 1, struct rule *);
	}

	return (error);
}

void
apply_result(struct expritem *ei, int *result, int this)
{
	if (ei->inverted)
		this = !this;
	switch (ei->op) {
	case OP_NONE:
		*result = this;
		break;
	case OP_OR:
		*result = *result || this;
		break;
	case OP_AND:
		*result = *result && this;
		break;
	}
}

int
mail_deliver(struct mail_ctx *mctx, struct msg *msg, struct msgbuf *msgbuf)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct deliver_ctx	*dctx;

	set_wrapped(m, '\n');

	/*
	 * If blocked, check for msgs from parent.
	 */
	if (mctx->msgid != 0) {
		if (msg == NULL || msg->id != mctx->msgid)
			return (MAIL_BLOCKED);
		mctx->msgid = 0;

		/*
		 * Got message. Finish delivery.
		 */
		dctx = TAILQ_FIRST(&mctx->dqueue);
		if (finish_action(dctx, msg, msgbuf) == ACTION_ERROR)
			return (MAIL_ERROR);

		/*
		 * Move on to dequeue this delivery action.
		 */
		goto done;
	}

	/*
	 * Check if delivery is complete.
	 */
	if (TAILQ_EMPTY(&mctx->dqueue))
		return (MAIL_MATCH);

	/*
	 * Get the first delivery action and start it.
	 */
	dctx = TAILQ_FIRST(&mctx->dqueue);
	switch (start_action(mctx, dctx)) {
	case ACTION_ERROR:
		return (MAIL_ERROR);
	case ACTION_PARENT:
		return (MAIL_BLOCKED);
	}

done:
	/*
	 * Remove completed action from queue.
	 */
	TAILQ_REMOVE(&mctx->dqueue, dctx, entry);
	log_debug("%s: message %u delivered (rule %u, %s) in %.3f seconds",
	    a->name, m->idx, dctx->rule->idx,
	    dctx->actitem->deliver->name, get_time() - dctx->tim);
	xfree(dctx);
	return (MAIL_CONTINUE);
}

struct users *
find_delivery_users(struct mail_ctx *mctx, struct action *t, int *should_free)
{
	struct account	*a = mctx->account;
	struct mail	*m = mctx->mail;
	struct rule	*r = mctx->rule;
	struct users	*users;

	*should_free = 0;
	users = NULL;
	if (r->find_uid) {			/* rule comes first */
		*should_free = 1;
		users = find_users(m);
	} else if (r->users != NULL) {
		*should_free = 0;
		users = r->users;
	} else if (t != NULL && t->find_uid) {	/* then action */
		*should_free = 1;
		users = find_users(m);
	} else if (t != NULL && t->users != NULL) {
		*should_free = 0;
		users = t->users;
	} else if (a->find_uid) {		/* then account */
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
fill_delivery_queue(struct mail_ctx *mctx, struct rule *r)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct action		*t;
	struct actions		*ta;
	u_int		 	 i, j;
	char			*s;
	struct replstr		*rs;
	struct users		*users;
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
			users = find_delivery_users(mctx, t, &should_free);
			
			fill_delivery_action(mctx, r, t, users);
			
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

void
fill_delivery_action(struct mail_ctx *mctx, struct rule *r, struct action *t,
    struct users *users)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct actitem		*ti;
	struct deliver_ctx	*dctx;
	u_int			 i;

	for (i = 0; i < ARRAY_LENGTH(users); i++) {
		TAILQ_FOREACH(ti, t->list, entry) {
			dctx = xcalloc(1, sizeof *dctx);
			dctx->action = t;
			dctx->actitem = ti;
			dctx->account = a;
			dctx->rule = r;
			dctx->mail = m;
			dctx->uid = ARRAY_ITEM(users, i, uid_t);

			log_debug3("%s: action %s:%u (%s), uid %lu", a->name,
			    t->name, ti->idx, ti->deliver->name, 
			    (u_long) dctx->uid);
			TAILQ_INSERT_TAIL(&mctx->dqueue, dctx, entry);
		}
	}
}

int
start_action(struct mail_ctx *mctx, struct deliver_ctx *dctx)
{
	struct account	*a = dctx->account;
	struct action	*t = dctx->action;
 	struct actitem	*ti = dctx->actitem;
	struct mail	*m = dctx->mail;
	struct msg	 msg;
	struct msgbuf	 msgbuf;

	dctx->tim = get_time();
	log_debug2("%s: message %u, running action %s:%u (%s) as user %lu",
	    a->name, m->idx, t->name, ti->idx, ti->deliver->name,
	    (u_long) dctx->uid);
	add_tag(&m->tags, "action", "%s", t->name);

	/* just deliver now for in-child delivery */
	if (ti->deliver->type == DELIVER_INCHILD) {
		if (ti->deliver->deliver(dctx, ti) != DELIVER_SUCCESS)
			return (ACTION_ERROR);
		return (ACTION_DONE);
	}

	memset(&msg, 0, sizeof msg);
	msg.type = MSG_ACTION;
	msg.id = m->idx;

	msg.data.account = a;
	msg.data.actitem = ti;
	msg.data.uid = dctx->uid;

	msgbuf.buf = m->tags;
	msgbuf.len = STRB_SIZE(m->tags);

	mail_send(m, &msg);

	log_debug3("%s: sending action to parent", a->name);
	if (privsep_send(mctx->io, &msg, &msgbuf) != 0)
		fatalx("child: privsep_send error");

	mctx->msgid = msg.id;
	return (ACTION_PARENT);
}

int
finish_action(struct deliver_ctx *dctx, struct msg *msg, struct msgbuf *msgbuf)
{
	struct account	*a = dctx->account;
 	struct actitem	*ti = dctx->actitem;
	struct mail	*m = dctx->mail;
	u_int		 lines;

	if (msgbuf->buf != NULL && msgbuf->len != 0) {
		strb_destroy(&m->tags);
		m->tags = msgbuf->buf;
		update_tags(&m->tags);
	}

	if (msg->data.error != 0)
		return (ACTION_ERROR);

	if (ti->deliver->type != DELIVER_WRBACK)
		return (ACTION_DONE);

	if (mail_receive(m, msg, 1) != 0) {
		log_warn("%s: can't receive mail", a->name);
		return (ACTION_ERROR);
	}
	log_debug2("%s: message %u, received modified mail: size %zu, body %zd",
	    a->name, m->idx, m->size, m->body);

	/* trim from line */
	trim_from(m);

	/* and recreate the wrapped array */
	lines = fill_wrapped(m);
	log_debug2("%s: found %u wrapped lines", a->name, lines);

	return (ACTION_DONE);
}
