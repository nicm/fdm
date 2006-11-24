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
#include <sys/time.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fdm.h"

int	poll_account(struct io *, struct account *);
int	fetch_account(struct io *, struct account *);
int	do_expr(struct rule *, struct match_ctx *);
int	do_deliver(struct rule *, struct match_ctx *);
int	do_action(struct rule *, struct match_ctx *, struct action *);
int	do_rules(struct match_ctx *, struct rules *, const char **);

int
child(int fd, enum fdmop op)
{
	struct io	*io;
	struct msg	 msg;
	struct account	*a;
	int		 rc, error;

#ifdef DEBUG
	xmalloc_clear();
	COUNTFDS("child");
#endif

        SSL_library_init();
        SSL_load_error_strings();

	io = io_create(fd, NULL, IO_LF);
	log_debug("child: started, pid %ld", (long) getpid());

	if (geteuid() != 0)
		log_debug("child: not root user. not dropping privileges");
	else {
		log_debug("child: changing to user %lu",
		    (u_long) conf.child_uid);
		if (dropto(conf.child_uid) != 0)
			fatal("dropto");
        }
#ifndef NO_SETPROCTITLE
	setproctitle("child");
#endif

        log_debug("child: processing accounts");

	rc = 0;
	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (!check_incl(a->name)) {
			log_debug("child: account %s is not included", a->name);
			continue;
		}
		if (check_excl(a->name)) {
			log_debug("child: account %s is excluded", a->name);
			continue;
		}
		/* if the account is disabled and no accounts are specified
		   on the command line (whether or not it is included if there
		   are is already confirmed), then skip it */
		if (a->disabled && ARRAY_EMPTY(&conf.incl)) {
			log_debug("child: account %s is disabled", a->name);
			continue;
		}

		log_debug("child: processing account %s", a->name);

		/* connect */
		if (a->fetch->connect != NULL) {
			if (a->fetch->connect(a) != 0) {
				rc = 1;
				continue;
			}
		}

		/* process */
		error = 0;
		switch (op) {
		case FDMOP_POLL:
			error = poll_account(io, a);
			break;
		case FDMOP_FETCH:
			error = fetch_account(io, a);
			break;
		default:
			fatalx("child: unexpected command");
		}
		if (error != 0) {
			if (a->fetch->error != NULL)
				a->fetch->error(a);
			rc = 1;
		}

		/* disconnect */
		if (a->fetch->disconnect != NULL)
			a->fetch->disconnect(a);
	}

        log_debug("child: finished processing. exiting");

	msg.type = MSG_EXIT;
	if (privsep_send(io, &msg, NULL, 0) != 0)
		fatalx("parent: privsep_send error");

	io_free(io);

#ifdef DEBUG
	COUNTFDS("child");
	xmalloc_dump("child");
#endif

	return (rc);
}

int
poll_account(unused struct io *io, struct account *a)
{
	u_int	n;

	if (a->fetch->poll == NULL) {
		log_info("%s: polling not supported", a->name);
		return (1);
	}
	log_debug("%s: polling", a->name);

	if (a->fetch->poll(a, &n) == POLL_ERROR) {
		log_warnx("%s: polling error. aborted", a->name);
		return (1);
	}

	log_info("%s: %u messages found", a->name, n);

	return (0);
}

int
fetch_account(struct io *io, struct account *a)
{
	struct mail	 m;
	struct timeval	 tv;
	double		 tim;
	u_int	 	 n, l;
	int		 error, matched, stopped, delete;
 	const char	*cause = NULL;
	struct match_ctx mctx;
	char		*hdr;
	size_t		 len;

	if (a->fetch->fetch == NULL) {
		log_info("%s: fetching not supported", a->name);
		return (1);
	}
	log_debug("%s: fetching", a->name);

	gettimeofday(&tv, NULL);
	tim = tv.tv_sec + tv.tv_usec / 1000000.0;

	n = 0;
        for (;;) {
		delete = 1;
		if (conf.keep_all || a->keep)
			delete = 0;

		memset(&m, 0, sizeof m);
		m.body = -1;
		ARRAY_INIT(&m.tags);

		memset(&mctx, 0, sizeof mctx);
		mctx.io = io;
		mctx.account = a;
		mctx.mail = &m;
		mctx.matched = &matched;
		mctx.stopped = &stopped;

		error = a->fetch->fetch(a, &m);
		switch (error) {
		case FETCH_ERROR:
			cause = "fetching";
			goto out;
		case FETCH_OVERSIZE:
			log_warnx("%s: message too big: %zu bytes", a->name,
			    m.size);
			if (!conf.del_big) {
				cause = "fetching";
				goto out;
			}
			goto done;
		case FETCH_COMPLETE:
			goto out;
		}

		trim_from(&m);
		if (m.size == 0) {
			free_mail(&m, 1);
			log_warnx("%s: got empty message. ignored", a->name);
			continue;
		}

		log_debug("%s: got message: size=%zu, body=%zd", a->name,
		    m.size, m.body);

		hdr = find_header(&m, "message-id:", &len);
		if (hdr == NULL || len == 0 || len > INT_MAX)
			log_debug("%s: no message-id", a->name);
		else {
			log_debug("%s: message-id is: %.*s", a->name, (int) len,
			    hdr);
		}

		l = fill_wrapped(&m);
		log_debug2("%s: found %u wrapped lines", a->name, l);

		/* handle rule evaluation and actions */
		matched = stopped = 0;
		if (do_rules(&mctx, &conf.rules, &cause) != 0)
			goto out;

		if (stopped)
			goto done;

		switch (conf.impl_act) {
		case IMPLICIT_NONE:
			log_warnx("%s: reached end of ruleset. no "
			    "unmatched-mail option; mail kept",  a->name);
			delete = 0;
			break;
		case IMPLICIT_KEEP:
			log_debug("%s: reached end of ruleset. mail kept",
			    a->name);
			delete = 0;
			break;
		case IMPLICIT_DROP:
			log_debug("%s: reached end of ruleset. mail dropped",
			    a->name);
			break;
		}

	done:
		/* finished with the message */
		if (delete) {
			if (a->fetch->delete != NULL) {
				log_debug("%s: deleting message", a->name);
				if (a->fetch->delete(a) != 0) {
					cause = "deleting";
					goto out;
				}
			}
		} else {
			if (a->fetch->keep != NULL) {
				log_debug("%s: keeping message", a->name);
				if (a->fetch->keep(a) != 0) {
					cause = "keeping";
					goto out;
				}
			}
		}

 		free_mail(&m, 1);
		n++;
	}

out:
	free_mail(&m, 1);
	if (cause != NULL)
		log_warnx("%s: %s error. aborted", a->name, cause);

	if (gettimeofday(&tv, NULL) != 0)
		fatal("gettimeofday");
	tim = (tv.tv_sec + tv.tv_usec / 1000000.0) - tim;
	if (n > 0) {
		log_info("%s: %u messages processed in %.3f seconds "
		    "(average %.3f)", a->name, n, tim, tim / n);
	} else {
	        log_info("%s: %u messages processed in %.3f seconds",
		    a->name, n, tim);
	}

	return (cause != NULL);
}

int
do_rules(struct match_ctx *mctx, struct rules *rules, const char **cause)
{
	struct rule		*r;
	struct accounts		*list;
	u_int		 	 i;
	int		 	 error;
	char			*name;
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;

	TAILQ_FOREACH(r, rules, entry) {
		/* check if the rule is for the current account */
		list = r->accounts;
		if (!ARRAY_EMPTY(list)) {
			for (i = 0; i < ARRAY_LENGTH(list); i++) {
				name = ARRAY_ITEM(list, i, char *);
				if (name_match(name, a->name))
					break;
			}
			if (i == ARRAY_LENGTH(list))
				continue;
		}

		/* match all the regexps */
		switch (r->type) {
		case RULE_EXPRESSION:
			if ((error = do_expr(r, mctx)) == -1) {
				*cause = "matching";
				return (1);
			}
			/* continue if no match */
			if (!error)
				continue;
			break;
		case RULE_ALL:
			break;
		}
		set_wrapped(m, '\n');

		/* tag mail if needed */
		if (r->tag != NULL) {
			log_debug("%s: tagging message: %s", a->name, r->tag);
			ARRAY_ADD(&m->tags, r->tag, char *);
		}

		/* handle delivery */
		if (r->actions != NULL) {
			log_debug("%s: matched message", a->name);
			*mctx->matched = 1;
			if (do_deliver(r, mctx) != 0) {
				*cause = "delivery";
				return (1);
			}
		}
		/* deal with nested rules */
		if (!TAILQ_EMPTY(&r->rules)) {
			log_debug2("%s: entering nested rules", a->name);
			if (do_rules(mctx, &r->rules, cause) != 0)
				return (1);
			log_debug2("%s: exiting nested rules%s", a->name,
			    *mctx->stopped ? ", and stopping" : "");
			/* if it didn't drop off the end of the nested rules,
			   stop now */
			if (*mctx->stopped)
				return (0);
		}

		/* if this rule is marked as stop, stop checking now */
		if (r->stop) {
			*mctx->stopped = 1;
			return (0);
		}
	}

	return (0);
}

int
do_expr(struct rule *r, struct match_ctx *mctx)
{
	int		 fres, cres;
	struct expritem	*ei;
	char		*s;

	set_wrapped(mctx->mail, ' ');

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

		s = ei->match->desc(ei);
		log_debug2("%s: tried %s%s:%s, got %d", mctx->account->name,
		    ei->inverted ? "not " : "", ei->match->name, s, cres);
		xfree(s);
	}

	return (fres);
}

int
do_deliver(struct rule *r, struct match_ctx *mctx)
{

 	struct action		*t;
	struct actionptrs	*ta;
	u_int		 	 i, j;
	char		        *s, *name;
	struct account		*a = mctx->account;

	if (r->actions == NULL)
		return (0);

	for (i = 0; i < ARRAY_LENGTH(r->actions); i++) {
		name = ARRAY_ITEM(r->actions, i, char *);

		if (mctx->pmatch_valid)
			s = replacepmatch(name, mctx->mail, mctx->pmatch);
		else
			s = xstrdup(name);

		log_debug2("%s: looking for actions matching: %s", a->name, s);
		ta = find_actions(s);
		if (ARRAY_EMPTY(ta)) {
			log_warnx("%s: can't any find actions matching: %s "
			    "(was %s)", a->name, s, name);
			xfree(s);
			ARRAY_FREEALL(ta);
			return (1);
		}
		xfree(s);

		log_debug2("%s: found %u actions", a->name, ARRAY_LENGTH(ta));
		for (j = 0; j < ARRAY_LENGTH(ta); j++) {
			t = ARRAY_ITEM(ta, j, struct action *);
			log_debug2("%s: action %s", a->name, t->name);
			if (do_action(r, mctx, t) != 0) {
				ARRAY_FREEALL(ta);
				return (1);
			}
		}

		ARRAY_FREEALL(ta);
	}

	return (0);
}

int
do_action(struct rule *r, struct match_ctx *mctx, struct action *t)
{
	struct account		*a = mctx->account;
	struct mail		*m = mctx->mail;
	struct msg	 	 msg;
	struct tags		 tags;
	struct deliver_ctx	 dctx;
	u_int		 	 i, l;
	int		 	 find;
	struct users	        *users;

 	if (t->deliver->deliver == NULL)
		return (0);

	/* just deliver now for in-child delivery */
	if (t->deliver->type == DELIVER_INCHILD) {
		memset(&dctx, 0, sizeof dctx);
		dctx.account = a;
		dctx.mail = m;

		if (t->deliver->deliver(&dctx, t) != DELIVER_SUCCESS)
			return (1);
		return (0);
	}

	/* figure out the users to use */
	users = NULL;
	if (r->find_uid) {		/* rule comes first */
		find = 1;
		users = find_users(m);
	} else if (r->users != NULL) {
		find = 0;
		users = r->users;
	} else if (t->find_uid) {
		find = 1;
		users = find_users(m);
	} else if (t->users != NULL) {	/* then action */
		find = 0;
		users = t->users;
	}
	if (users == NULL) {
		find = 1;
		users = xmalloc(sizeof *users);
		ARRAY_INIT(users);
		ARRAY_ADD(users, conf.def_user, uid_t);
	}

	for (i = 0; i < ARRAY_LENGTH(users); i++) {
		msg.type = MSG_ACTION;
		msg.data.account = a;
		msg.data.action = t;
		msg.data.uid = ARRAY_ITEM(users, i, uid_t);
		copy_mail(m, &msg.data.mail);
		if (privsep_send(mctx->io, &msg, NULL, 0) != 0)
			fatalx("child: privsep_send error");

		if (privsep_recv(mctx->io, &msg, NULL, 0) != 0)
			fatalx("child: privsep_recv error");
		if (msg.type != MSG_DONE)
			fatalx("child: unexpected message");
		if (msg.data.error != 0) {
			ARRAY_FREEALL(users);
			return (1);
		}

		if (t->deliver->type != DELIVER_WRBACK)
			continue;

		/* save the tags */
		memcpy(&tags, &m->tags, sizeof tags);
		ARRAY_INIT(&m->tags);

		/* free the old mail */
		free_mail(m, 1);

		/* copy the new mail in and reopen it */
		memcpy(m, &msg.data.mail, sizeof *m);
		m->base = shm_reopen(&m->shm);
		m->data = m->base + m->off;

		/* restore the tags */
		memcpy(&m->tags, &tags, sizeof tags);

		log_debug("%s: received modified mail: size %zu, body=%zd",
		    a->name, m->size, m->body);

		/* trim from line */
		trim_from(m);

		/* and recreate the wrapped array */
		l = fill_wrapped(m);
		log_debug2("%s: found %u wrapped lines", a->name, l);

		/* invalidate the pmatch data since stuff may have moved */
		mctx->pmatch_valid = 0;
	}

	if (find)
		ARRAY_FREEALL(users);

	return (0);
}
