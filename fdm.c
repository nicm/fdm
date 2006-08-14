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

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

#ifdef DEBUG
char			*malloc_options = "AFGJX";
#endif

extern FILE		*yyin;
extern int 		 yyparse(void);

int			 load_conf(void);
void			 usage(void);
void			 poll_account(struct account *);
void			 fetch_account(struct account *);
int			 perform_match(struct account *, struct mail *,
			     struct rule *);

struct conf		 conf;

int
load_conf(void)
{
        yyin = fopen(conf.conf_file, "r");
        if (yyin == NULL)
                return (1);

        yyparse();

        fclose(yyin);

        return (0);
}

__dead void
usage(void)
{
	printf("usage: %s [-lnv] [-f conffile] [-a account] [-x account] "
	    "[fetch|poll]\n", __progname);
        exit(1);
}

int
main(int argc, char **argv)
{
	struct passwd	*pw;
        int		 opt;
	u_int		 i;
	char		*cmd = NULL, tmp[128];
	struct account	*a;
	struct accounts	 incl, excl;

	memset(&conf, 0, sizeof conf);
	TAILQ_INIT(&conf.accounts);
	TAILQ_INIT(&conf.rules);
	TAILQ_INIT(&conf.actions);
	conf.max_size = MAXMAILSIZE;
	conf.lock_types = LOCK_FLOCK;

	log_init(1);

	ACCOUNTS_INIT(&incl);  
	ACCOUNTS_INIT(&excl);

        while ((opt = getopt(argc, argv, "a:f:lnvx:")) != EOF) {
                switch (opt) {
		case 'a':
			ACCOUNTS_ADD(&incl, optarg);
			break;
                case 'f':
                        conf.conf_file = xstrdup(optarg);
                        break;
		case 'l':
			conf.syslog = 1;
			break;
		case 'n':
			conf.check_only = 1;
			break;
                case 'v':
                        conf.debug++;
                        break;
		case 'x':
			ACCOUNTS_ADD(&excl, optarg);
			break;
                case '?':
                default:
                        usage();
                }
        }
	argc -= optind;
	argv += optind;
	if (conf.check_only) {
		if (argc != 0)
			usage();
	} else {		
		if (argc != 1)
			usage();
		cmd = argv[0];
		if (strcmp(cmd, "poll") != 0 && strcmp(cmd, "fetch") != 0)
			usage();
	}

	/* start logging to syslog if necessary */
	log_init(!conf.syslog);
	log_debug("version is: %s " BUILD, __progname);

	/* save the home dir and misc user info */
	conf.home = getenv("HOME");
	if (conf.home != NULL && *conf.home == '\0')
		conf.home = NULL;
	pw = getpwuid(getuid());
	if (pw != NULL) {
		if (conf.home == NULL) {
			if (pw->pw_dir != NULL && *pw->pw_dir != '\0')
				conf.home = xstrdup(pw->pw_dir);
			else
				conf.home = xstrdup(".");
		}
		if (pw->pw_name != NULL && *pw->pw_name != '\0')
			conf.user = xstrdup(pw->pw_name);
		endpwent();
	} 
	if (conf.user == NULL) {
		xasprintf(&conf.user, "%llu", (unsigned long long) getuid());
		log_warn("can't find name for user %llu", 
		    (unsigned long long) getuid());
	}
	log_debug("user is: %s, home is: %s", conf.user, conf.home);

	/* find the config file */
	if (conf.conf_file == NULL)
		xasprintf(&conf.conf_file, "%s/%s", conf.home, CONFFILE);
	log_debug("loading configuration from %s", conf.conf_file);
        if (load_conf() != 0) {
                log_warn("%s", conf.conf_file);
		exit(1);
	}
	log_debug("configuration loaded");

	/* print some locking info */
	*tmp = '\0';
	if (conf.lock_types == 0)
		strlcpy(tmp, "none", sizeof tmp);
	else {
		if (conf.lock_types & LOCK_FCNTL)
			strlcat(tmp, "fcntl ", sizeof tmp);
		if (conf.lock_types & LOCK_FLOCK)
			strlcat(tmp, "flock ", sizeof tmp);
		if (conf.lock_types & LOCK_DOTLOCK)
			strlcat(tmp, "dotlock ", sizeof tmp);
	}
	log_debug("locking using: %s", tmp);

	/* if -n, bail now, otherwise check there is something to work with */
	if (conf.check_only) 
		exit(0);
        if (TAILQ_EMPTY(&conf.accounts)) {
                log_warnx("no accounts specified");
		exit(1);
	}
        if (strcmp(cmd, "fetch") == 0 && TAILQ_EMPTY(&conf.rules)) {
                log_warnx("no rules specified");
		exit(1);
	}

        SSL_library_init();
        SSL_load_error_strings();

        log_debug("processing accounts");
	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (!ACCOUNTS_EMPTY(&incl)) {
			/* check include list */
			for (i = 0; i < incl.num; i++) {
				if (strcmp(incl.list[i], a->name) == 0)
					break;
			}
			if (i == incl.num) {
				log_debug("account %s not included. skipping",
				    a->name);
				continue;
			}
		}
		if (!ACCOUNTS_EMPTY(&excl)) {
			/* check exclude list */
			for (i = 0; i < excl.num; i++) {
				if (strcmp(excl.list[i], a->name) == 0)
					break;
			}
			if (i != excl.num) {
				log_debug("account %s excluded. skipping",
				    a->name);
				continue;
			}
		}

		log_debug("processing account %s", a->name);

		/* connect */
		if (a->fetch->connect != NULL) {
			if (a->fetch->connect(a) != 0)
				continue;
		}

		/* process */
		if (strcmp(cmd, "poll") == 0)
			poll_account(a);
		else if (strcmp(cmd, "fetch") == 0)
			fetch_account(a);

		/* disconnect */
		if (a->fetch->disconnect != NULL)
			a->fetch->disconnect(a);
	}

        log_debug("finished processing. exiting");

	return (0);
}

void
poll_account(struct account *a)
{
	u_int	n;

	if (a->fetch->poll == NULL) {
		log_info("%s: polling not supported", a->name);
		return;
	}

	log_debug("%s: polling", a->name);

	if (a->fetch->poll(a, &n) == 0)
		log_info("%s: %u messages found", a->name, n);
}

void
fetch_account(struct account *a)
{
	struct rule	*r;
	struct mail	 m;
	struct action	*t;
	struct timeval	 tv;
	double		 tim;
	u_int	 	 n, i;
	int		 cancel;
	struct accounts	*list;

	if (a->fetch->fetch == NULL) {
		log_info("%s: fetching not supported", a->name);
		return;
	}

	gettimeofday(&tv, NULL);
	tim = tv.tv_sec + tv.tv_usec / 1000000.0;

	log_debug("%s: fetching", a->name);

	n = 0;
	cancel = 0;
        for (;;) {
		memset(&m, 0, sizeof m);
		m.body = -1;
		if (a->fetch->fetch(a, &m) != 0)
			return;
		if (m.data == NULL || m.size == 0) {
			if (m.data != NULL)
				xfree(m.data);
			break;
		}
		
		log_debug("%s: got message: size=%zu, body=%zu", a->name,
		    m.size, m.body);

		i = fill_wrapped(&m);
		log_debug("%s: found %u wrapped lines", a->name, i);

		TAILQ_FOREACH(r, &conf.rules, entry) {
			list = r->accounts;
			if (!ACCOUNTS_EMPTY(list)) {
				for (i = 0; i < list->num; i++) {
					if (strcmp(list->list[i], a->name) == 0)
						break;
				}
				if (i == list->num)
					continue;
			}
				
			if (!perform_match(a, &m, r))
				continue;

			t = r->action;
			log_debug("%s: matched message: action=%s", 
			    a->name, t->name);
				
			if (t->deliver->deliver == NULL) {
				if (r->stop)
					break;
				continue;
			}

			set_wrapped(&m, '\n');
			if (t->deliver->deliver(a, r->action, &m) != 0) {
				/* delivery error, abort fetching */
				cancel = 1;
				break;
			}
			if (r->stop)
				break;
		}

		free_mail(&m);

		if (cancel) {
			log_warnx("%s: processing error. aborted", a->name);
			break;
		}

		n++;
	}

	gettimeofday(&tv, NULL);
	tim = (tv.tv_sec + tv.tv_usec / 1000000.0) - tim;
	log_info("%s: %u messages processed in %.3f seconds", a->name, n, tim);
}

int
perform_match(struct account *a, struct mail *m, struct rule *r)
{
	regmatch_t	 pmatch;
	int		 matched, result;
	struct match	*c;

	if (r->matches == NULL)
		return (1);

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
		log_debug("%s: tried \"%s\": got %d", a->name, c->s, result);
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
