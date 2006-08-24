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
#include <sys/socket.h>

#include <errno.h>
#include <grp.h>
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

void
fill_info(char *home)
{
	struct passwd	*pw;
	uid_t		 uid;

	if (conf.info.uid != NULL) {
		xfree(conf.info.uid);
		conf.info.uid = NULL;
	}
	if (conf.info.user != NULL) {
		xfree(conf.info.user);
		conf.info.user = NULL;
	}
	if (conf.info.home != NULL) {
		xfree(conf.info.home);
		conf.info.home = NULL;
	}

	if (home != NULL && *home != '\0')
		conf.info.home = xstrdup(home);

	uid = getuid();
	xasprintf(&conf.info.uid, "%lu", (u_long) uid);
	pw = getpwuid(uid);
	if (pw != NULL) {
		if (conf.info.home == NULL) {
			if (pw->pw_dir != NULL && *pw->pw_dir != '\0')
				conf.info.home = xstrdup(pw->pw_dir);
			else
				conf.info.home = xstrdup(".");
		}
		if (pw->pw_name != NULL && *pw->pw_name != '\0')
			conf.info.user = xstrdup(pw->pw_name);
		endpwent();
	} 
	if (conf.info.user == NULL) {
		conf.info.user = xstrdup(conf.info.uid);
		log_warn("can't find name for user %lu", (u_long) uid);
	}
}

int
dropto(uid_t uid, char *path)
{
	struct passwd	*pw;

	pw = getpwuid(uid);
	if (pw == NULL) {
		errno = ESRCH;
		return (1);
	}
	
	if (path != NULL) {
		if (chroot(conf.child_path) != 0)
			return (1);
	}

	if (setgroups(1, &pw->pw_gid) != 0 ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0 ||
	    setresuid(uid, uid, uid) != 0)
		return (1);

	endpwent();
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
        int		 opt, fds[2];
	enum cmd         cmd = CMD_NONE;
	char		 tmp[128];
	pid_t		 pid;
	struct passwd	*pw;

	memset(&conf, 0, sizeof conf);
	TAILQ_INIT(&conf.accounts);
	TAILQ_INIT(&conf.rules);
	TAILQ_INIT(&conf.actions);
	conf.max_size = DEFMAILSIZE;
	conf.lock_types = LOCK_FLOCK;

	log_init(1);

	ARRAY_INIT(&conf.incl);  
	ARRAY_INIT(&conf.excl);

        while ((opt = getopt(argc, argv, "a:f:lnvx:")) != EOF) {
                switch (opt) {
		case 'a':
			ARRAY_ADD(&conf.incl, optarg, sizeof (char *));
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
			ARRAY_ADD(&conf.excl, optarg, sizeof (char *));
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
		if (strcmp(argv[0], "poll") == 0)
			cmd = CMD_POLL;
		else if (strcmp(argv[0], "fetch") == 0)
			cmd = CMD_FETCH;
		else
			usage();
	}

	/* start logging to syslog if necessary */
	log_init(!conf.syslog);
	log_debug("version is: %s " BUILD, __progname);

	/* save the home dir and misc user info */
	fill_info(getenv("HOME"));
	log_debug("user is: %s, home is: %s", conf.info.user, conf.info.home);

	/* find the config file */
	if (conf.conf_file == NULL)
		xasprintf(&conf.conf_file, "%s/%s", conf.info.home, CONFFILE);
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
        if (cmd == CMD_FETCH && TAILQ_EMPTY(&conf.rules)) {
                log_warnx("no rules specified");
		exit(1);
	}
	
	if (geteuid() == 0) {
		pw = getpwnam(CHILDUSER);
		if (pw == NULL) {
			log_warnx("can't find user: %s", CHILDUSER);
			exit(1);
		}
		conf.child_uid = pw->pw_uid;
		if (pw->pw_dir == NULL || *pw->pw_dir == '\0') {
			log_warnx("cannot find home for user: %s", CHILDUSER);
			exit(1);
		}
		conf.child_path = xstrdup(pw->pw_dir);
		endpwent();

		if (conf.def_user == 0) {
			log_warnx("no default user specified");
			exit(1);
		}			
	}

#ifdef DEBUG
	xmalloc_clear();
#endif

        SSL_library_init();
        SSL_load_error_strings();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, fds) != 0)
		fatal("socketpair");
	switch (pid = fork()) {
	case -1:
		fatal("fork");
	case 0:
		close(fds[0]);
		_exit(child(fds[1], cmd));
	default:
		close(fds[1]);
		exit(parent(fds[0], pid));
	}
}
