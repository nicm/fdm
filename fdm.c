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

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"

#ifdef DEBUG
const char		*malloc_options = "AFGJPX";
#endif

extern FILE		*yyin;
extern int 		 yyparse(void);

void			 sighandler(int);
int			 load_conf(void);
void			 usage(void);

struct conf		 conf;

volatile sig_atomic_t	 sigint;
volatile sig_atomic_t	 sigterm;

void
sighandler(int sig)
{
	switch (sig) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGTERM:
		sigterm = 1;
		break;
	}
}

double
get_time(void)
{
	struct timeval	 tv;

	if (gettimeofday(&tv, NULL) != 0)
		fatal("gettimeofday");
	return (tv.tv_sec + tv.tv_usec / 1000000.0);
}

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
fill_info(const char *home)
{
	struct passwd	*pw;
	uid_t		 uid;
	char		 host[MAXHOSTNAMELEN];

	uid = getuid();
	if (conf.info.valid && conf.info.last_uid == uid)
		return;
	conf.info.valid = 1;
	conf.info.last_uid = uid;

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

	if (conf.info.host == NULL) {
		if (gethostname(host, sizeof host) != 0)
			fatal("gethostname");
		conf.info.host = xstrdup(host);

		fill_fqdn(host, &conf.info.fqdn, &conf.info.addr);
	}

	if (home != NULL && *home != '\0')
		conf.info.home = xstrdup(home);

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
	}
	endpwent();
	if (conf.info.user == NULL) {
		conf.info.user = xstrdup(conf.info.uid);
		log_warnx("can't find name for user %lu", (u_long) uid);
	}
}

void
fill_fqdn(char *host, char **fqdn, char **addr)
{
	char			 ni[NI_MAXHOST];
	struct addrinfo		*ai;

	*fqdn = *addr = NULL;

	if (getaddrinfo(host, NULL, NULL, &ai) != 0)
		return;

	if (getnameinfo(ai->ai_addr,
	    ai->ai_addrlen, ni, sizeof ni, NULL, 0, NI_NUMERICHOST) == 0)
		xasprintf(addr, "[%s]", ni);

	if (getnameinfo(ai->ai_addr,
	    ai->ai_addrlen, ni, sizeof ni, NULL, 0, NI_NAMEREQD) == 0)
		*fqdn = xstrdup(ni);
}

int
dropto(uid_t uid)
{
	struct passwd	*pw;
	gid_t		 gid;

	if (uid == NOUSR || uid == 0)
		return (0);

	pw = getpwuid(uid);
	if (pw == NULL) {
		endpwent();
		errno = ESRCH;
		return (1);
	}
	gid = pw->pw_gid;
	endpwent();

	if (setgroups(1, &gid) != 0 ||
	    setresgid(gid, gid, gid) != 0 || setresuid(uid, uid, uid) != 0)
		return (1);

	return (0);
}

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
use_account(struct account *a, char **cause)
{
	if (!check_incl(a->name)) {
		if (cause != NULL)
			xasprintf(cause, "account %s is not included", a->name);
		return (0);
	}
	if (check_excl(a->name)) {
		if (cause != NULL)
			xasprintf(cause, "account %s is excluded", a->name);
		return (0);
	}

	/*
	 * If the account is disabled and no accounts are specified on the
	 * command line (whether or not it is included if there are is already
	 * confirmed), then skip it.
	 */
	if (a->disabled && ARRAY_EMPTY(&conf.incl)) {
		if (cause != NULL)
			xasprintf(cause, "account %s is disabled", a->name);
		return (0);
	}

	return (1);
}

__dead void
usage(void)
{
	printf("usage: %s [-klmnqv] [-a name] [-D name=value] [-f conffile]"
	    " [-u user] [-x name] [fetch|poll]\n", __progname);
        exit(1);
}

int
main(int argc, char **argv)
{
        int		 opt, lockfd, status, res;
	u_int		 i;
	enum fdmop       op = FDMOP_NONE;
	const char	*errstr, *proxy = NULL, *s;
	char		 tmp[1024], *ptr, *strs, *user = NULL, *lock = NULL;
	long		 n;
	struct utsname	 un;
	struct passwd	*pw;
	struct stat	 sb;
	time_t		 tt;
	struct account	*a;
	pid_t		 pid;
	struct children	 children, dead_children;
	struct child	*child;
	struct io      **ios, *io;
	double		 tim;
	struct sigaction act;
	struct msg	 msg;
	struct msgbuf	 msgbuf;
	size_t		 off;
	struct macro	*macro;
	struct child_fetch_data *cfd;
#ifdef DEBUG
	struct rule	*r;
	struct action	*t;
#endif

	memset(&conf, 0, sizeof conf);
	TAILQ_INIT(&conf.accounts);
	TAILQ_INIT(&conf.rules);
	TAILQ_INIT(&conf.actions);
	conf.max_size = DEFMAILSIZE;
	conf.timeout = DEFTIMEOUT;
	conf.lock_types = LOCK_FLOCK;
	conf.impl_act = DECISION_NONE;
	conf.purge_after = 0;
	conf.file_umask = DEFUMASK;
	conf.file_group = NOGRP;
	conf.queue_high = -1;
	conf.queue_low = -1;

	log_init(1);

	ARRAY_INIT(&conf.incl);
	ARRAY_INIT(&conf.excl);

        while ((opt = getopt(argc, argv, "a:D:f:klmnqu:vx:?")) != EOF) {
                switch (opt) {
		case 'a':
			ARRAY_ADD(&conf.incl, xstrdup(optarg), char *);
			break;
		case 'D':
			if (*optarg != '$' && *optarg != '%') {
				log_warnx("invalid macro: %s", optarg);
				exit(1);
			}
			ptr = strchr(optarg, '=');
			if (ptr != NULL)
				*ptr++ = '\0';
			if (strlen(optarg) > MAXNAMESIZE) {
				log_warnx("macro name too long: %s", optarg);
				exit(1);
			}

			macro = xmalloc(sizeof *macro);
			macro->fixed = 1;
			strlcpy(macro->name, optarg, sizeof macro->name);
			TAILQ_INSERT_HEAD(&macros, macro, entry);

			if (*optarg == '$') {
				macro->type = MACRO_STRING;
				if (ptr == NULL)
					macro->value.str = xstrdup("");
				else
					macro->value.str = xstrdup(ptr);
				log_debug2("added -D macro \"%s\": %s",
				    macro->name, macro->value.str);
				break;
			}

			macro->type = MACRO_NUMBER;
			if (ptr == NULL) {
				macro->value.num = 0;
				break;
			}
			macro->value.num = strtonum(ptr, 0, LLONG_MAX, &errstr);
			if (errstr != NULL) {
				log_warnx("number is %s: %s", errstr, ptr);
				exit(1);
			}
			log_debug2("added -D macro \"%s\": %lld", macro->name,
			    macro->value.num);
			break;
                case 'f':
                        conf.conf_file = xstrdup(optarg);
                        break;
		case 'k':
			conf.keep_all = 1;
			break;
		case 'l':
			conf.syslog = 1;
			break;
		case 'm':
			conf.allow_many = 1;
			break;
		case 'n':
			conf.check_only = 1;
			break;
		case 'u':
			user = optarg;
			break;
                case 'v':
                        conf.debug++;
                        break;
		case 'q':
			conf.quiet = 1;
			break;
		case 'x':
			ARRAY_ADD(&conf.excl, xstrdup(optarg), char *);
			break;
                case '?':
                default:
                        usage();
                }
        }
	argc -= optind;
	argv += optind;
	if (conf.quiet)
		conf.debug = 0;
	if (conf.check_only) {
		if (argc != 0)
			usage();
	} else {
		if (argc != 1)
			usage();
		if (strncmp(argv[0], "poll", strlen(argv[0])) == 0)
			op = FDMOP_POLL;
		else if (strncmp(argv[0], "fetch", strlen(argv[0])) == 0)
			op = FDMOP_FETCH;
		else
			usage();
	}

	/* check the user */
	if (user != NULL) {
		pw = getpwnam(user);
		if (pw == NULL) {
			n = strtonum(user, 0, UID_MAX, &errstr);
			if (errstr != NULL) {
				if (errno == ERANGE) {
					log_warnx("invalid uid: %s", user);
					exit(1);
				}
			} else
				pw = getpwuid((uid_t) n);
			if (pw == NULL) {
				log_warnx("unknown user: %s", user);
				exit(1);
			}
		}
		conf.def_user = pw->pw_uid;
		endpwent();
	}

	/* start logging to syslog if necessary */
	log_init(!conf.syslog);
	tt = time(NULL);
	log_debug("version is: %s " BUILD ", started at: %.24s", __progname,
	    ctime(&tt));

	/* and the OS version */
	if (uname(&un) == 0) {
		log_debug2("running on: %s %s %s %s", un.sysname, un.release,
		    un.version, un.machine);
	} else
		log_debug2("uname: %s", strerror(errno));

	/* save the home dir and misc user info and set the umask */
	fill_info(getenv("HOME"));
	log_debug2("user is: %s, home is: %s", conf.info.user, conf.info.home);

	/* find the config file */
	if (conf.conf_file == NULL) {
		/* if no file specified, try ~ then /etc */
		xasprintf(&conf.conf_file, "%s/%s", conf.info.home, CONFFILE);
		if (access(conf.conf_file, R_OK) != 0) {
			xfree(conf.conf_file);
			conf.conf_file = xstrdup(SYSCONFFILE);
		}
	}
	log_debug2("loading configuration from %s", conf.conf_file);
	if (stat(conf.conf_file, &sb) == -1) {
                log_warn("%s", conf.conf_file);
		exit(1);
	}
	if (geteuid() != 0 && (sb.st_mode & (S_IROTH|S_IWOTH)) != 0)
		log_warnx("%s: world readable or writable", conf.conf_file);
        if (load_conf() != 0) {
                log_warn("%s", conf.conf_file);
		exit(1);
	}
	log_debug2("configuration loaded");

	/* sort out queue limits */
	if (conf.queue_high == -1)
		conf.queue_high = DEFMAILQUEUE;
	if (conf.queue_low == -1) {
		conf.queue_low = conf.queue_high * 3 / 4;
		if (conf.queue_low >= conf.queue_high)
			conf.queue_low = conf.queue_high - 1;
 	}

	/* set the umask */
	umask(conf.file_umask);

	/* print proxy info */
	if (conf.proxy != NULL) {
		switch (conf.proxy->type) {
		case PROXY_HTTP:
			proxy = "HTTP";
			break;
		case PROXY_HTTPS:
			proxy = "HTTPS";
			break;
		case PROXY_SOCKS5:
			proxy = "SOCKS5";
			break;
		}
		log_debug2("using proxy: %s on %s:%s", proxy,
		    conf.proxy->server.host, conf.proxy->server.port);
	}

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
	log_debug2("locking using: %s", tmp);

	/* initialise and print headers and domains */
	if (conf.headers == NULL) {
		conf.headers = xmalloc(sizeof *conf.headers);
		ARRAY_INIT(conf.headers);
		ARRAY_ADD(conf.headers, xstrdup("to"), char *);
		ARRAY_ADD(conf.headers, xstrdup("cc"), char *);
	}
	strs = fmt_strings(NULL, conf.headers);
	log_debug2("headers are: %s", strs);
	xfree(strs);
	if (conf.domains == NULL) {
		conf.domains = xmalloc(sizeof *conf.headers);
		ARRAY_INIT(conf.domains);
		ARRAY_ADD(conf.domains, xstrdup(conf.info.host), char *);
		if (conf.info.fqdn != NULL) {
			ptr = xstrdup(conf.info.fqdn);
			ARRAY_ADD(conf.domains, ptr, char *);
		}
		if (conf.info.addr != NULL) {
			ptr = xstrdup(conf.info.addr);
			ARRAY_ADD(conf.domains, ptr, char *);
		}
	}
	strs = fmt_strings(NULL, conf.domains);
	log_debug2("domains are: %s", strs);
	xfree(strs);

	/* print the other settings */
	*tmp = '\0';
	off = 0;
	if (conf.allow_many)
		off = strlcat(tmp, "allow-multiple, ", sizeof tmp);
	if (conf.no_received)
		off = strlcat(tmp, "no-received, ", sizeof tmp);
	if (conf.keep_all)
		off = strlcat(tmp, "keep-all, ", sizeof tmp);
	if (conf.del_big)
		off = strlcat(tmp, "delete-oversized, ", sizeof tmp);
	if (sizeof tmp > off && conf.purge_after > 0) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "purge-after=%u, ", conf.purge_after);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "maximum-size=%zu, ", conf.max_size);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "timeout=%d, ", conf.timeout / 1000);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "default-user=%lu, ", (u_long) conf.def_user);
	}
	if (sizeof tmp > off && conf.impl_act != DECISION_NONE) {
		if (conf.impl_act == DECISION_DROP)
			s = "drop";
		else if (conf.impl_act == DECISION_KEEP)
			s = "keep";
		else
			s = "none";
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "unmatched-mail=%s, ", s);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "file-umask=%o%o%o, ", MODE(conf.file_umask));
	}
	if (sizeof tmp > off && conf.file_group != NOGRP) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "file-group=%lu, ", (u_long) conf.file_group);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off, 
		    "queue-high=%u, queue-low=%u, ", conf.queue_high,
		    conf.queue_low);
	}
	if (sizeof tmp > off && conf.lock_file != NULL) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "lock-file=\"%s\", ", conf.lock_file);
	}
	if (off >= 2) {
		tmp[off - 2] = '\0';
		log_debug2("options are: %s", tmp);
	}

	/* save and print tmp dir */
	s = getenv("TMPDIR");
	if (s == NULL || *s == '\0')
		s = _PATH_TMP;
	else {
		if (stat(s, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
			log_warn("%s", s);
			s = _PATH_TMP;
		}
	}
	conf.tmp_dir = xstrdup(s);
	while ((ptr = strrchr(conf.tmp_dir, '/')) != NULL) {
		if (ptr == conf.tmp_dir || ptr[1] != '\0')
			break;
		*ptr = '\0';
	}
	log_debug2("using tmp directory: %s", conf.tmp_dir);

	/* if -n, bail now, otherwise check there is something to work with */
	if (conf.check_only)
		exit(0);
        if (TAILQ_EMPTY(&conf.accounts)) {
                log_warnx("no accounts specified");
		exit(1);
	}
        if (op == FDMOP_FETCH && TAILQ_EMPTY(&conf.rules)) {
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
		conf.child_gid = pw->pw_gid;
		endpwent();

		if (conf.def_user == 0) {
			log_warnx("no default user specified");
			exit(1);
		}
	}

	/* set up signal handlers */
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGTERM);
	act.sa_flags = SA_RESTART;

	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) < 0)
		fatal("sigaction");
	if (sigaction(SIGUSR1, &act, NULL) < 0)
		fatal("sigaction");
	if (sigaction(SIGUSR2, &act, NULL) < 0)
		fatal("sigaction");

	act.sa_handler = sighandler;
	if (sigaction(SIGINT, &act, NULL) < 0)
		fatal("sigaction");
	if (sigaction(SIGTERM, &act, NULL) < 0)
		fatal("sigaction");

	/* check lock file */
	lock = conf.lock_file;
	if (lock == NULL) {
		if (geteuid() == 0)
			lock = xstrdup(SYSLOCKFILE);
		else
			xasprintf(&lock, "%s/%s", conf.info.home, LOCKFILE);
	}
	if (*lock != '\0' && !conf.allow_many) {
		lockfd = open(lock, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
		if (lockfd == -1 && errno == EEXIST) {
			log_warnx("already running (%s exists)", lock);
			exit(1);
		} else if (lockfd == -1) {
			log_warn("%s: open", lock);
			exit(1);
		}
		close(lockfd);
	}
	conf.lock_file = lock;

        SSL_library_init();
        SSL_load_error_strings();

#ifdef DEBUG
	COUNTFDS("parent");
#endif

	/* start the children and build the array */
	ARRAY_INIT(&children);
	ARRAY_INIT(&dead_children);

	child = NULL;
	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (!use_account(a, NULL))
			continue;

		cfd = xmalloc(sizeof *cfd);
		cfd->account = a;
		cfd->op = op;
		cfd->children = &children;
		child = child_start(&children, conf.child_uid, child_fetch,
		    parent_fetch, cfd);

		log_debug2("parent: child %ld (%s) started", (long) child->pid,
		    a->name);
	}

	if (ARRAY_EMPTY(&children)) {
                log_warnx("no accounts found");
		res = 1;
		goto out;
	}

#ifndef NO_SETPROCTITLE
	setproctitle("parent");
#endif
	log_debug2("parent: started, pid is %ld", (long) getpid());
	tim = get_time();

	res = 0;
	ios = NULL;
	while (!ARRAY_EMPTY(&children)) {
		if (sigint || sigterm)
			break;

		/* fill the io list */
		ios = xrealloc(ios, ARRAY_LENGTH(&children), sizeof **ios);
		for (i = 0; i < ARRAY_LENGTH(&children); i++) {
			child = ARRAY_ITEM(&children, i, struct child *);
			ios[i] = child->io;
		}

		/* poll the io list */
		n = io_polln(ios, ARRAY_LENGTH(&children), &io, INFTIM, NULL);
		switch (n) {
		case -1:
			fatalx("parent: child socket error");
		case 0:
			fatalx("parent: child socket closed");
		}

		while (!ARRAY_EMPTY(&children)) {
			/* check all children for pending privsep messages */
			for (i = 0; i < ARRAY_LENGTH(&children); i++) {
				child = ARRAY_ITEM(&children, i,struct child *);
				if (privsep_check(child->io))
					break;
			}
			if (i == ARRAY_LENGTH(&children))
				break;

			/* and handle them if necessary */
			if (privsep_recv(child->io, &msg, &msgbuf) != 0)
				fatalx("parent: privsep_recv error");
			log_debug3("parent: got message type %d, id %u from "
			    "child %ld", msg.type, msg.id, (long) child->pid);

			if (child->msg(child, &msg, &msgbuf) == 0)
				continue;

			/* child has said it is ready to exit, tell it to */
			memset(&msg, 0, sizeof msg);
			msg.type = MSG_EXIT;
			if (privsep_send(child->io, &msg, NULL) != 0)
				fatalx("parent: privsep_send error");

			/* wait for the child */
			if (waitpid(child->pid, &status, 0) == -1)
				fatal("waitpid");
			if (WIFSIGNALED(status)) {
				res = 1;
				log_debug2("parent: child %ld got signal %d",
				    (long) child->pid, WTERMSIG(status));
			} else if (!WIFEXITED(status)) {
				res = 1;
				log_debug2("parent: child %ld didn't exit"
				    "normally", (long) child->pid);
			} else {
				if (WEXITSTATUS(status) != 0)
					res = 1;
				log_debug2("parent: child %ld returned %d",
				    (long) child->pid, WEXITSTATUS(status));
			}

			io_close(child->io);

			ARRAY_REMOVE(&children, i, struct child *);
			ARRAY_ADD(&dead_children, child, struct child *);
		}
	}
	xfree(ios);

	/* free the dead children */
	for (i = 0; i < ARRAY_LENGTH(&dead_children); i++) {
		child = ARRAY_ITEM(&dead_children, i, struct child *);
		io_free(child->io);
		if (child->data != NULL)
			xfree(child->data);
		xfree(child);
	}
	ARRAY_FREE(&dead_children);

	if (sigint || sigterm) {
		act.sa_handler = SIG_IGN;
		if (sigaction(SIGINT, &act, NULL) < 0)
			fatal("sigaction");
		if (sigaction(SIGTERM, &act, NULL) < 0)
			fatal("sigaction");

		if (sigint)
			log_warnx("parent: caught SIGINT. stopping");
		else if (sigterm)
			log_warnx("parent: caught SIGTERM. stopping");

		/* kill the children */
		for (i = 0; i < ARRAY_LENGTH(&children); i++) {
			child = ARRAY_ITEM(&children, i,struct child *);
			kill(child->pid, SIGTERM);

			io_close(child->io);
			io_free(child->io);
			xfree(child);
		}
		ARRAY_FREE(&children);

		/* and wait for them */
		for (;;) {
			if ((pid = wait(&status)) == -1) {
				if (errno == ECHILD)
					break;
				fatal("wait");
			}
			log_debug2("parent: child %ld killed", (long) pid);
		}

		res = 1;
	}

	tim = get_time() - tim;
 	log_debug2("parent: finished, total time %.3f seconds", tim);

out:
	if (!conf.allow_many && *conf.lock_file != '\0')
		unlink(conf.lock_file);

#ifdef DEBUG
	COUNTFDS("parent");

	/* free everything */
	while (!TAILQ_EMPTY(&conf.accounts)) {
		a = TAILQ_FIRST(&conf.accounts);
		TAILQ_REMOVE(&conf.accounts, a, entry);
		free_account(a);
	}
	while (!TAILQ_EMPTY(&conf.rules)) {
		r = TAILQ_FIRST(&conf.rules);
		TAILQ_REMOVE(&conf.rules, r, entry);
		free_rule(r);
	}
	while (!TAILQ_EMPTY(&conf.actions)) {
		t = TAILQ_FIRST(&conf.actions);
		TAILQ_REMOVE(&conf.actions, t, entry);
		free_action(t);
	}
	xfree(conf.info.home);
	xfree(conf.info.user);
	xfree(conf.info.uid);
	xfree(conf.info.host);
	if (conf.info.fqdn != NULL)
		xfree(conf.info.fqdn);
	if (conf.info.addr != NULL)
		xfree(conf.info.addr);
	xfree(conf.conf_file);
	xfree(conf.lock_file);
	xfree(conf.tmp_dir);
	free_strings(conf.domains);
	ARRAY_FREEALL(conf.domains);
	free_strings(conf.headers);
	ARRAY_FREEALL(conf.headers);
	free_strings(&conf.incl);
	free_strings(&conf.excl);

	xmalloc_report("parent");
#endif

	exit(res);
}
