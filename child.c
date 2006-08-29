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

#include <fnmatch.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fdm.h"

int	check_incl(char *);
int	check_excl(char *);
int	poll_account(struct io *, struct account *);
int	fetch_account(struct io *, struct account *);
int	perform_match(struct account *, struct mail *, struct rule *);

int
check_incl(char *name) 
{
	u_int	i;

	if (ARRAY_EMPTY(&conf.incl))
		return (1);

	for (i = 0; i < ARRAY_LENGTH(&conf.incl); i++) {
		if (name_match(ARRAY_ITEM(&conf.incl, i, char *), name))
			return (1);
	}

	return (0);
}

int
check_excl(char *name) 
{
	u_int	i;

	if (ARRAY_EMPTY(&conf.excl))
		return (0);

	for (i = 0; i < ARRAY_LENGTH(&conf.excl); i++) {
		if (name_match(ARRAY_ITEM(&conf.excl, i, char *), name))
			return (1);
	}

	return (0);
}

int
child(int fd, enum cmd cmd)
{
	struct io	*io;
	struct msg	 msg;
	struct account	*a;
	int		 rc, error;

#ifdef DEBUG
	xmalloc_clear();
#endif

	io = io_create(fd, NULL, IO_LF);
	log_debug("child: started, pid %ld", (long) getpid());

	if (geteuid() != 0)
		log_debug("child: not root user. not dropping privileges");
	else {
		log_debug("child: changing to user %lu, path %s",
		    (u_long) conf.child_uid, conf.child_path);
		if (dropto(conf.child_uid, conf.child_path) != 0)
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
			if (a->fetch->connect(a) != 0)
				continue;
		}
		
		/* process */
		error = 0;
		switch (cmd) {
		case CMD_POLL:
			error = poll_account(io, a);
			break;
		case CMD_FETCH:
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
	io_write(io, &msg, sizeof msg);
	io_flush(io);

	io_free(io);

#ifdef DEBUG
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

	if (a->fetch->poll(a, &n) == POLL_ERROR)
		return (1);

	log_info("%s: %u messages found", a->name, n);

	return (0);
}

int
fetch_account(struct io *io, struct account *a)
{
	struct msg	 msg;
	struct rule	*r;
	struct mail	 m;
	struct timeval	 tv;
	double		 tim;
	u_int	 	 n, i;
	int		 error, matched;
	char		*name, *cause = NULL;
	struct accounts	*list;

	if (a->fetch->fetch == NULL) {
		log_info("%s: fetching not supported", a->name);
		return (1);
	}
	log_debug("%s: fetching", a->name);

	gettimeofday(&tv, NULL);
	tim = tv.tv_sec + tv.tv_usec / 1000000.0;

	n = 0;
        for (;;) {
		memset(&m, 0, sizeof m);
		m.body = -1;

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
			goto delete;
		case FETCH_COMPLETE:
			goto out;
		}

		log_debug("%s: got message: size=%zu, body=%zd", a->name,
		    m.size, m.body);

		i = fill_wrapped(&m);
		log_debug2("%s: found %u wrapped lines", a->name, i);

		matched = 0;
		TAILQ_FOREACH(r, &conf.rules, entry) {
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
			case RULE_MATCHES:
				if (!perform_match(a, &m, r))
					continue;
				break;
			case RULE_ALL:
				break;
			case RULE_MATCHED:
				if (!matched)
					continue;
				break;
			case RULE_UNMATCHED:
				if (matched)
					continue;
				break;
			}
			log_debug("%s: matched message", a->name);
			matched = 1;

			set_wrapped(&m, '\n');

			/* pass up to the parent for delivery */
			msg.type = MSG_DELIVER;
			msg.rule = r;
			msg.acct = a;
			memcpy(&msg.mail, &m, sizeof msg.mail);
			msg.mail.wrapped = NULL;
			io_write(io, &msg, sizeof msg);
			if (io_flush(io) != 0)
				fatalx("child: io_flush error");
			io_write(io, m.data, m.size);
			if (io_flush(io) != 0)
				fatalx("child: io_flush error");
			if (io_wait(io, sizeof msg) != 0)
				fatalx("child: io_wait error");
			if (io_read2(io, &msg, sizeof msg) != 0)
				fatalx("child: io_read2 error");
			if (msg.type != MSG_DONE)
				fatalx("child: unexpected message");
			if (msg.error != 0) {
				cause = "delivery";
				goto out;
			}

			/* if this rule is marked as stop, stop checking
			   the rules now */
			if (r->stop)
				break;
		}

	delete:
		/* delete the message */
		if (a->fetch->delete != NULL) {
			log_debug("%s: deleting message", a->name);
			if (a->fetch->delete(a) != 0) {
				cause = "deleting";
				goto out;
			}
		}

 		free_mail(&m);
		n++;
	}

out:	
	free_mail(&m);
	if (cause != NULL)
		log_warnx("%s: %s error. aborted", a->name, cause);

	gettimeofday(&tv, NULL);
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
perform_match(struct account *a, struct mail *m, struct rule *r)
{
	regmatch_t	 pmatch;
	int		 matched, result;
	struct match	*c;

	set_wrapped(m, ' ');

	matched = 0;
	TAILQ_FOREACH(c, r->matches, entry) {
		if (c->area == AREA_BODY && m->body == -1)
			continue;
		switch (c->area) {
		case AREA_HEADERS:
			pmatch.rm_so = 0;
			if (m->body == -1)
				pmatch.rm_eo = m->size;
			else
				pmatch.rm_eo = m->body;
			break;
		case AREA_BODY:
			pmatch.rm_so = m->body;
			pmatch.rm_eo = m->size;
			break;
		case AREA_ANY:
			pmatch.rm_so = 0;
			pmatch.rm_eo = m->size;
			break;
		}
		
		result = !regexec(&c->re, m->data, 0, &pmatch, REG_STARTEND);
		if (c->inverted)
			result = !result;
		log_debug2("%s: tried %s\"%s\": got %d", a->name, 
		    c->inverted ? "!" : "", c->s, result);
		switch (c->op) {
		case OP_NONE:
		case OP_OR:
			matched = matched || result;
			break;
		case OP_AND:
			matched = matched && result;
			break;
		}
	}

	return (matched);
}
