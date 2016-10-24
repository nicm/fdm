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

#include <fnmatch.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"
#include "match.h"

void		 apply_result(struct expritem *, int *, int);

struct replstrs	*find_delivery_users(struct mail_ctx *, struct action *, int *);
int		 fill_from_strings(struct mail_ctx *, struct rule *,
		     struct replstrs *);
int		 fill_from_string(struct mail_ctx *, struct rule *,
		     struct replstr *);
int		 fill_from_action(struct mail_ctx *, struct rule *,
		     struct action *, struct replstrs *);

int		 start_action(struct mail_ctx *, struct deliver_ctx *);
int		 finish_action(struct deliver_ctx *, struct msg *,
		    struct msgbuf *);

#define ACTION_DONE 0
#define ACTION_ERROR 1
#define ACTION_PARENT 2

/*
 * Number of chained actions. Limit on recursion with things like:
 *
 *	action "name" { action "name" }
 */
u_int	chained;

/* Check mail against next rule or part of expression. */
int
mail_match(struct mail_ctx *mctx, struct msg *msg, struct msgbuf *msgbuf)
{
	struct account	*a = mctx->account;
	struct mail	*m = mctx->mail;
	struct expritem	*ei;
	struct replstrs	*users;
	int		 should_free, this = -1, error = MAIL_CONTINUE;
	char		 desc[DESCBUFSIZE];

	set_wrapped(m, ' ');

	/* If blocked, check for msgs from parent. */
	if (mctx->msgid != 0) {
		if (msg == NULL || msg->id != mctx->msgid)
			return (MAIL_BLOCKED);
		mctx->msgid = 0;

		if (msg->type != MSG_DONE)
			fatalx("unexpected message");
		if (msgbuf->buf != NULL && msgbuf->len != 0) {
			strb_destroy(&m->tags);
			m->tags = msgbuf->buf;
			reset_tags(&m->tags);
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
			fatalx("unexpected response");
		}
		apply_result(ei, &mctx->result, this);

		goto next_expritem;
	}

	/* Check for completion and end of ruleset. */
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

	/* Expression not started. Start it. */
	if (mctx->expritem == NULL) {
		/* Start the expression. */
		mctx->result = 0;
		mctx->expritem = TAILQ_FIRST(mctx->rule->expr);
	}

	/* Check this expression item and adjust the result. */
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
		fatalx("unexpected op");
	}
	apply_result(ei, &mctx->result, this);

	ei->match->desc(ei, desc, sizeof desc);
	log_debug3("%s: tried %s, result now %d", a->name, desc, mctx->result);

next_expritem:
	/* Move to the next item. If there is one, then return. */
	mctx->expritem = TAILQ_NEXT(mctx->expritem, entry);
	if (mctx->expritem != NULL)
		return (MAIL_CONTINUE);

	log_debug3("%s: finished rule %u, result %d", a->name, mctx->rule->idx,
	    mctx->result);

	/* If the result was false, skip to find the next rule. */
	if (!mctx->result)
		goto next_rule;
	log_debug2("%s: matched to rule %u", a->name, mctx->rule->idx);

	/*
	 * If this rule is stop, mark the context so when we get back after
	 * delivery we know to stop.
	 */
	if (mctx->rule->stop)
		mctx->done = 1;

	/* Handle nested rules. */
	if (!TAILQ_EMPTY(&mctx->rule->rules)) {
		log_debug2("%s: entering nested rules", a->name);

		/*
		 * Stack the current rule (we are at the end of it so the
		 * the expritem must be NULL already).
		 */
		ARRAY_ADD(&mctx->stack, mctx->rule);

		/* Continue with the first rule of the nested list. */
		mctx->rule = TAILQ_FIRST(&mctx->rule->rules);
		return (MAIL_CONTINUE);
	}
	mctx->matched = 1;

	/* Handle lambda actions. */
	if (mctx->rule->lambda != NULL) {
		users = find_delivery_users(mctx, NULL, &should_free);

		chained = MAXACTIONCHAIN;
		if (fill_from_action(mctx,
		    mctx->rule, mctx->rule->lambda, users) != 0) {
			if (should_free)
				ARRAY_FREEALL(users);
			return (MAIL_ERROR);
		}

		if (should_free)
			ARRAY_FREEALL(users);
		error = MAIL_DELIVER;
	}

	/* Fill the delivery action queue. */
	if (!ARRAY_EMPTY(mctx->rule->actions)) {
		chained = MAXACTIONCHAIN;
		if (fill_from_strings(mctx,
		    mctx->rule, mctx->rule->actions) != 0)
			return (MAIL_ERROR);
		error = MAIL_DELIVER;
	}

next_rule:
	/* Move to the next rule. */
	mctx->ruleidx = mctx->rule->idx;	/* save last index */
	mctx->rule = TAILQ_NEXT(mctx->rule, entry);

	/* If no more rules, try to move up the stack. */
	while (mctx->rule == NULL) {
		if (ARRAY_EMPTY(&mctx->stack))
			break;
		log_debug2("%s: exiting nested rules", a->name);
		mctx->rule = ARRAY_LAST(&mctx->stack);
		mctx->rule = TAILQ_NEXT(mctx->rule, entry);
		ARRAY_TRUNC(&mctx->stack, 1);
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

/* Run next delivery action. */
int
mail_deliver(struct mail_ctx *mctx, struct msg *msg, struct msgbuf *msgbuf)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct deliver_ctx	*dctx;

	set_wrapped(m, '\n');

	/* If blocked, check for msgs from parent. */
	if (mctx->msgid != 0) {
		if (msg == NULL || msg->id != mctx->msgid)
			return (MAIL_BLOCKED);
		mctx->msgid = 0;

		/* Got message. Finish delivery. */
		dctx = TAILQ_FIRST(&mctx->dqueue);
		if (finish_action(dctx, msg, msgbuf) == ACTION_ERROR)
			return (MAIL_ERROR);

		/* Move on to dequeue this delivery action. */
		goto done;
	}

	/* Check if delivery is complete. */
	if (TAILQ_EMPTY(&mctx->dqueue))
		return (MAIL_MATCH);

	/* Get the first delivery action and start it. */
	dctx = TAILQ_FIRST(&mctx->dqueue);
	switch (start_action(mctx, dctx)) {
	case ACTION_ERROR:
		return (MAIL_ERROR);
	case ACTION_PARENT:
		return (MAIL_BLOCKED);
	}

done:
	/* Remove completed action from queue. */
	TAILQ_REMOVE(&mctx->dqueue, dctx, entry);
	log_debug("%s: message %u delivered (rule %u, %s) in %.3f seconds",
	    a->name, m->idx, dctx->rule->idx,
	    dctx->actitem->deliver->name, get_time() - dctx->tim);
	user_free(dctx->udata);
	xfree(dctx);
	return (MAIL_CONTINUE);
}

struct replstrs *
find_delivery_users(struct mail_ctx *mctx, struct action *t, int *should_free)
{
	struct account	*a = mctx->account;
	struct rule	*r = mctx->rule;
	struct replstrs	*users;

	*should_free = 0;
	users = NULL;
	if (r->users != NULL)			/* rule comes first */
		users = r->users;
	else if (t != NULL && t->users != NULL)	/* then action */
		users = t->users;
	else if (a->users != NULL)		/* then account */
		users = a->users;
	if (users == NULL) {
		*should_free = 1;
		users = xmalloc(sizeof *users);
		ARRAY_INIT(users);
		ARRAY_EXPAND(users, 1);
		ARRAY_LAST(users).str = conf.def_user;
	}

	return (users);
}

int
fill_from_strings(struct mail_ctx *mctx, struct rule *r, struct replstrs *rsa)
{
	struct account	*a = mctx->account;
	u_int		  i;
	struct replstr	*rs;

	chained--;
	if (chained == 0) {
		log_warnx("%s: too many chained actions", a->name);
		return (-1);
	}

	for (i = 0; i < ARRAY_LENGTH(rsa); i++) {
		rs = &ARRAY_ITEM(rsa, i);
		if (fill_from_string(mctx, r, rs) != 0)
			return (-1);
	}

	return (0);
}

int
fill_from_string(struct mail_ctx *mctx, struct rule *r, struct replstr *rs)
{
	struct account	*a = mctx->account;
	struct mail	*m = mctx->mail;
	struct action	*t;
	struct actions	*ta;
	u_int		 i;
	char		*s;
	struct replstrs *users;
	int		 should_free;

	s = replacestr(rs, m->tags, m, &m->rml);

	log_debug2("%s: looking for actions matching: %s", a->name, s);
	ta = match_actions(s);
	if (ARRAY_EMPTY(ta))
		goto empty;
	xfree(s);

	log_debug2("%s: found %u actions", a->name, ARRAY_LENGTH(ta));
	for (i = 0; i < ARRAY_LENGTH(ta); i++) {
		t = ARRAY_ITEM(ta, i);
		users = find_delivery_users(mctx, t, &should_free);

		if (fill_from_action(mctx, r, t, users) != 0) {
			if (should_free)
				ARRAY_FREEALL(users);
			ARRAY_FREEALL(ta);
			return (-1);
		}

		if (should_free)
			ARRAY_FREEALL(users);
	}

	ARRAY_FREEALL(ta);
	return (0);

empty:
	log_warnx("%s: no actions matching: %s (%s)", a->name, s, rs->str);
	xfree(s);
	ARRAY_FREEALL(ta);
	return (-1);
}

int
fill_from_action(struct mail_ctx *mctx, struct rule *r, struct action *t,
    struct replstrs *users)
{
	struct account			*a = mctx->account;
	struct mail			*m = mctx->mail;
	struct deliver_action_data	*data;
	struct actitem			*ti;
	struct deliver_ctx		*dctx;
	u_int				 i;
	char				*user;
	struct userdata			*udata;

	for (i = 0; i < ARRAY_LENGTH(users); i++) {
		user = replacestr(&ARRAY_ITEM(users, i), m->tags, m, &m->rml);
		if (user == NULL || *user == '\0') {
			if (user != NULL)
				xfree(user);
			log_warnx("%s: empty user", a->name);
			return (-1);
		}
		if ((udata = user_lookup(user, conf.user_order)) == NULL) {
			log_warnx("%s: bad user: %s", a->name, user);
			xfree(user);
			return (-1);
		}
		xfree(user);

		TAILQ_FOREACH(ti, t->list, entry) {
			if (ti->deliver == NULL) {
				data = ti->data;
				if (fill_from_strings(
				    mctx, r, data->actions) != 0) {
					user_free(udata);
					return (-1);
				}
				continue;
			}

			dctx = xcalloc(1, sizeof *dctx);
			dctx->action = t;
			dctx->actitem = ti;
			dctx->account = a;
			dctx->rule = r;
			dctx->mail = m;

			dctx->udata = user_copy(udata);

			log_debug3("%s: action %s:%u (%s), user %s", a->name,
			    t->name, ti->idx, ti->deliver->name,
			    ARRAY_ITEM(users, i).str);
			TAILQ_INSERT_TAIL(&mctx->dqueue, dctx, entry);
		}

		user_free(udata);
	}

	return (0);
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
	log_debug2("%s: message %u, running action %s:%u (%s) as user %s",
	    a->name, m->idx, t->name, ti->idx, ti->deliver->name,
	    dctx->udata->name);
	add_tag(&m->tags, "action", "%s", t->name);
	add_tag(&m->tags, "rule", "%u", mctx->ruleidx);

	update_tags(&m->tags, dctx->udata);

	/* Just deliver now for in-child delivery. */
	if (ti->deliver->type == DELIVER_INCHILD) {
		if (ti->deliver->deliver(dctx, ti) != DELIVER_SUCCESS) {
			reset_tags(&m->tags);
			return (ACTION_ERROR);
		}

		reset_tags(&m->tags);
		return (ACTION_DONE);
	}

	memset(&msg, 0, sizeof msg);
	msg.type = MSG_ACTION;
	msg.id = m->idx;

	msg.data.account = a;
	msg.data.actitem = ti;

	msg.data.uid = dctx->udata->uid;
	msg.data.gid = dctx->udata->gid;

	msgbuf.buf = m->tags;
	msgbuf.len = STRB_SIZE(m->tags);

	mail_send(m, &msg);

	log_debug3("%s: sending action to parent", a->name);
	if (privsep_send(mctx->io, &msg, &msgbuf) != 0)
		fatalx("privsep_send error");

	mctx->msgid = msg.id;

	reset_tags(&m->tags);
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
		reset_tags(&m->tags);
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

	/* Trim from line. */
	trim_from(m);

	/* Recreate the wrapped array. */
	lines = fill_wrapped(m);
	log_debug2("%s: found %u wrapped lines", a->name, lines);

	return (ACTION_DONE);
}
