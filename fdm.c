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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "fdm.h"

#if defined(__OpenBSD__) && defined(DEBUG)
const char		*malloc_options = "AFGJPRX";
#endif

void			 sighandler(int);
struct child		*check_children(struct children *, u_int *);

struct conf		 conf;

volatile sig_atomic_t	 sigusr1;
volatile sig_atomic_t	 sigint;
volatile sig_atomic_t	 sigterm;

void
sighandler(int sig)
{
	switch (sig) {
#ifdef SIGINFO
	case SIGINFO:
#endif
	case SIGUSR1:
		sigusr1 = 1;
		break;
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
		fatal("gettimeofday failed");
	return (tv.tv_sec + tv.tv_usec / 1000000.0);
}

void
fill_host(void)
{
	char	host[MAXHOSTNAMELEN];

	if (gethostname(host, sizeof host) != 0)
		fatal("gethostname failed");
	conf.host_name = xstrdup(host);
	getaddrs(host, &conf.host_fqdn, &conf.host_address);
}

void
dropto(uid_t uid, gid_t gid)
{
	if (uid == (uid_t) -1 || uid == 0)
		return;
	if (gid == (gid_t) -1 || gid == 0)
		return;

	if (setgroups(1, &gid) != 0)
		fatal("setgroups failed");
	if (setresgid(gid, gid, gid) != 0)
		fatal("setresgid failed");
	if (setresuid(uid, uid, uid) != 0)
		fatal("setresuid failed");
}

int
check_incl(const char *name)
{
	u_int	i;

	if (ARRAY_EMPTY(&conf.incl))
		return (1);

	for (i = 0; i < ARRAY_LENGTH(&conf.incl); i++) {
		if (account_match(ARRAY_ITEM(&conf.incl, i), name))
			return (1);
	}

	return (0);
}

int
check_excl(const char *name)
{
	u_int	i;

	if (ARRAY_EMPTY(&conf.excl))
		return (0);

	for (i = 0; i < ARRAY_LENGTH(&conf.excl); i++) {
		if (account_match(ARRAY_ITEM(&conf.excl, i), name))
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

/* Check each child for a privsep message. */
struct child *
check_children(struct children *children, u_int *idx)
{
	struct child	*child;

	for (*idx = 0; *idx < ARRAY_LENGTH(children); (*idx)++) {
		child = ARRAY_ITEM(children, *idx);
		if (child->io != NULL && privsep_check(child->io))
			return (child);
	}
	return (NULL);
}	

__dead void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-hklmnqv] [-a name] [-D name=value] [-f conffile] "
	    "[-u user] [-x name] [fetch|poll|cache] [arguments]\n", __progname);
        exit(1);
}

int
main(int argc, char **argv)
{
        int		 opt, lockfd, status, res;
	u_int		 i;
	enum fdmop       op = FDMOP_NONE;
	const char	*proxy = NULL, *s;
	char		 tmp[BUFSIZ], *ptr, *lock = NULL, *user, *home = NULL;
	long		 n;
	struct utsname	 un;
	struct passwd	*pw;
	struct stat	 sb;
	time_t		 tt;
	struct account	*a;
	TAILQ_HEAD(, account) actaq; /* active accounts */
	pid_t		 pid;
	struct children	 children, dead_children;
	struct child	*child, *child2;
	struct io       *rio;
	struct iolist	 iol;
	double		 tim;
	struct sigaction act;
	struct msg	 msg;
	struct msgbuf	 msgbuf;
	size_t		 off;
	struct strings	 macros;
	struct child_fetch_data *cfd;
	struct userdata *ud;
#ifdef DEBUG
	struct rule	*r;
	struct action	*t;
	struct cache	*cache;
#endif

	log_open_tty(0);

	memset(&conf, 0, sizeof conf);
	TAILQ_INIT(&conf.accounts);
	TAILQ_INIT(&conf.rules);
	TAILQ_INIT(&conf.actions);
	TAILQ_INIT(&conf.caches);
	conf.max_size = DEFMAILSIZE;
	conf.timeout = DEFTIMEOUT;
	conf.lock_types = LOCK_FLOCK;
	conf.impl_act = DECISION_NONE;
	conf.purge_after = 0;
	conf.file_umask = DEFUMASK;
	conf.file_group = -1;
	conf.queue_high = -1;
	conf.queue_low = -1;
	conf.def_user = NULL;
	conf.cmd_user = NULL;
	conf.max_accts = -1;
	conf.strip_chars = xstrdup(DEFSTRIPCHARS);

	conf.user_order = xmalloc(sizeof *conf.user_order);
	ARRAY_INIT(conf.user_order);
	ARRAY_ADD(conf.user_order, passwd_lookup);

	ARRAY_INIT(&conf.incl);
	ARRAY_INIT(&conf.excl);

	ARRAY_INIT(&macros);
        while ((opt = getopt(argc, argv, "a:D:f:hklmnqu:vx:")) != -1) {
                switch (opt) {
		case 'a':
			ARRAY_ADD(&conf.incl, xstrdup(optarg));
			break;
		case 'D':
			ARRAY_ADD(&macros, optarg);
			break;
                case 'f':
			if (conf.conf_file == NULL)
				conf.conf_file = xstrdup(optarg);
                        break;
		case 'h':
			home = getenv("HOME");
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
			if (conf.def_user == NULL)
				conf.def_user = xstrdup(optarg);
			break;
                case 'v':
			if (conf.debug != -1)
				conf.debug++;
                        break;
		case 'q':
			conf.debug = -1;
			break;
		case 'x':
			ARRAY_ADD(&conf.excl, xstrdup(optarg));
			break;
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
		if (argc < 1)
			usage();
		if (strncmp(argv[0], "poll", strlen(argv[0])) == 0) {
			if (argc != 1)
				usage();
			op = FDMOP_POLL;
		} else if (strncmp(argv[0], "fetch", strlen(argv[0])) == 0) {
			if (argc != 1)
				usage();
			op = FDMOP_FETCH;
		} else if (strncmp(argv[0], "cache", strlen(argv[0])) == 0)
			op = FDMOP_CACHE;
		else
			usage();
	}

	/* Set debug level and start logging to syslog if necessary. */
	if (conf.syslog)
		log_open_syslog(conf.debug);
	else
		log_open_tty(conf.debug);
	tt = time(NULL);
	log_debug("version is: %s " BUILD ", started at: %.24s", __progname,
	    ctime(&tt));

	/* And the OS version. */
	if (uname(&un) == 0) {
		log_debug2("running on: %s %s %s %s", un.sysname, un.release,
		    un.version, un.machine);
	} else
		log_debug2("uname: %s", strerror(errno));

	/* Fill the hostname. */
	fill_host();
	log_debug2("host is: %s %s %s",
	    conf.host_name, conf.host_fqdn, conf.host_address);

	/* Find invoking user's details. */
	if ((pw = getpwuid(getuid())) == NULL) {
		log_warnx("unknown user: %lu", (u_long) geteuid());
		exit(1); 
	}
 	user = xstrdup(pw->pw_name);
	if (home != NULL && *home != '\0')
		conf.user_home = xstrdup(home);
	else
		conf.user_home = xstrdup(pw->pw_dir);
	log_debug2("home is: %s", conf.user_home);
	endpwent();

	/* Find the config file. */
	if (conf.conf_file == NULL) {
		/* If no file specified, try ~ then /etc. */
		xasprintf(&conf.conf_file, "%s/%s", conf.user_home, CONFFILE);
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
        if (parse_conf(conf.conf_file, &macros) != 0) {
                log_warn("%s", conf.conf_file);
		exit(1);
	}
	ARRAY_FREE(&macros);
	log_debug2("configuration loaded");

	/* Fill in users if not set already in configuration file. */
	if (conf.def_user == NULL)
		conf.def_user = xstrdup(user);
	if (conf.cmd_user == NULL)
		conf.cmd_user = xstrdup(user);
	xfree(user);

	/* Sort out queue limits. */
	if (conf.queue_high == -1)
		conf.queue_high = DEFMAILQUEUE;
	if (conf.queue_low == -1) {
		conf.queue_low = conf.queue_high * 3 / 4;
		if (conf.queue_low >= conf.queue_high)
			conf.queue_low = conf.queue_high - 1;
 	}

	/* Set the umask. */
	umask(conf.file_umask);

	/* Check default and command users. */
	if (conf.def_user == NULL) {
		ud = user_lookup(conf.def_user, conf.user_order);
		if (ud == NULL) {
			log_warnx("unknown user: %s", conf.def_user);
			exit(1); 
		}
		user_free(ud);
	}
	if (conf.cmd_user == NULL) {
		ud = user_lookup(conf.cmd_user, conf.user_order);
		if (ud == NULL) {
			log_warnx("unknown user: %s", conf.cmd_user);
			exit(1); 
		}
		user_free(ud);
	}

	/* Print proxy info. */
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

	/* Print some locking info. */
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

	/* Print the other settings. */
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
	if (conf.verify_certs)
		off = strlcat(tmp, "verify-certificates, ", sizeof tmp);
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
		    "default-user=\"%s\", ", conf.def_user);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "command-user=\"%s\", ", conf.cmd_user);
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
	if (sizeof tmp > off && conf.file_group != (gid_t) -1) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "file-group=%lu, ", (u_long) conf.file_group);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "queue-high=%u, queue-low=%u, ", conf.queue_high,
		    conf.queue_low);
	}
	if (sizeof tmp > off && conf.max_accts != -1) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "parallel-accounts=%d ", conf.max_accts);
	}
	if (sizeof tmp > off && conf.lock_file != NULL) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "lock-file=\"%s\", ", conf.lock_file);
	}
	if (sizeof tmp > off) {
		off += xsnprintf(tmp + off, (sizeof tmp) - off,
		    "strip-characters=\"%s\", ", conf.strip_chars);
	}
	if (off >= 2) {
		tmp[off - 2] = '\0';
		log_debug2("options are: %s", tmp);
	}

	/* Save and print tmp dir. */
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

	/* If -n, bail now, otherwise check there is something to work with. */
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

	/* Change to handle cache ops. */
	if (op == FDMOP_CACHE) {
		argc--;
		argv++;
		cache_op(argc, argv);
	}

	/* Check for child user if root. */
	if (geteuid() == 0) {
		pw = getpwnam(CHILDUSER);
		if (pw == NULL) {
			log_warnx("can't find user: %s", CHILDUSER);
			exit(1);
		}
		conf.child_uid = pw->pw_uid;
		conf.child_gid = pw->pw_gid;
		endpwent();
	}

	/* Set up signal handlers. */
	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
#ifdef SIGINFO
	sigaddset(&act.sa_mask, SIGINFO);
#endif
	sigaddset(&act.sa_mask, SIGUSR1);
	sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGTERM);
	act.sa_flags = SA_RESTART;

	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) < 0)
		fatal("sigaction failed");
	if (sigaction(SIGUSR1, &act, NULL) < 0)
		fatal("sigaction failed");
	if (sigaction(SIGUSR2, &act, NULL) < 0)
		fatal("sigaction failed");

	act.sa_handler = sighandler;
#ifdef SIGINFO
	if (sigaction(SIGINFO, &act, NULL) < 0)
		fatal("sigaction failed");
#endif
	if (sigaction(SIGUSR1, &act, NULL) < 0)
		fatal("sigaction failed");
	if (sigaction(SIGINT, &act, NULL) < 0)
		fatal("sigaction failed");
	if (sigaction(SIGTERM, &act, NULL) < 0)
		fatal("sigaction failed");

	/* Check lock file. */
	lock = conf.lock_file;
	if (lock == NULL) {
		if (geteuid() == 0)
			lock = xstrdup(SYSLOCKFILE);
		else
			xasprintf(&lock, "%s/%s", conf.user_home, LOCKFILE);
	}
	if (*lock != '\0' && !conf.allow_many) {
		lockfd = xcreate(lock, O_WRONLY, -1, -1, S_IRUSR|S_IWUSR);
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

	/* Filter account list. */
	TAILQ_INIT(&actaq);
	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (use_account(a, NULL))
			TAILQ_INSERT_HEAD(&actaq, a, active_entry);
	}
	if (TAILQ_EMPTY(&actaq)) {
                log_warnx("no accounts found");
		res = 1;
		goto out;
	}

	/* Initialise the child process arrays. */
	ARRAY_INIT(&children);
	ARRAY_INIT(&dead_children);

#ifdef HAVE_SETPROCTITLE
	setproctitle("parent");
#endif
	log_debug2("parent: started, pid is %ld", (long) getpid());
	tim = get_time();

	res = 0;
	ARRAY_INIT(&iol);
	while (!TAILQ_EMPTY(&actaq) || ARRAY_LENGTH(&children) != 0) {
		log_debug2("parent: %u children, %u dead children",
		    ARRAY_LENGTH(&children), ARRAY_LENGTH(&dead_children));
		
		/* Stop on signal. */
		if (sigint || sigterm)
			break;

		/* While there is space, start another child. */
		while (!TAILQ_EMPTY(&actaq) && (conf.max_accts < 0 ||
		    ARRAY_LENGTH(&children) < (u_int) conf.max_accts)) {
			a = TAILQ_FIRST(&actaq);
			TAILQ_REMOVE(&actaq, a, active_entry);
			
			cfd = xmalloc(sizeof *cfd);
			cfd->account = a;
			cfd->op = op;
			cfd->children = &children;
			child = child_start(&children, 
			    conf.child_uid, conf.child_gid, 
			    child_fetch, parent_fetch, cfd, NULL);
			log_debug2("parent: child %ld (%s) started", 
			    (long) child->pid, a->name);	
		}

		/* Fill the io list. */
		ARRAY_CLEAR(&iol);
		for (i = 0; i < ARRAY_LENGTH(&children); i++) {
			child = ARRAY_ITEM(&children, i);
			ARRAY_ADD(&iol, child->io);
		}

		/* Poll the io list. */
		n = io_polln(
		    ARRAY_DATA(&iol), ARRAY_LENGTH(&iol), &rio, INFTIM, NULL);
		switch (n) {
		case -1:
			fatalx("child socket error");
		case 0:
			fatalx("child socket closed");
		}
		
		/* Check all children for pending privsep messages. */
		while ((child = check_children(&children, &i)) != NULL) {
			/* Handle this message. */
			if (privsep_recv(child->io, &msg, &msgbuf) != 0)
				fatalx("privsep_recv error");
			log_debug3("parent: got message type %d, id %u from "
			    "child %ld", msg.type, msg.id, (long) child->pid);
			if (child->msg(child, &msg, &msgbuf) == 0)
				continue;
		
			/* Child has said it is ready to exit, tell it to. */
			memset(&msg, 0, sizeof msg);
			msg.type = MSG_EXIT;
			if (privsep_send(child->io, &msg, NULL) != 0)
				fatalx("privsep_send error");
		
			/* Wait for the child. */
			if (waitpid(child->pid, &status, 0) == -1)
				fatal("waitpid failed");
			if (WIFSIGNALED(status)) {
				res = 1;
				log_debug2("parent: child %ld got signal %d",
				    (long) child->pid, WTERMSIG(status));
			} else if (!WIFEXITED(status)) {
				res = 1;
				log_debug2("parent: child %ld exited badly",
				    (long) child->pid);
			} else {
				if (WEXITSTATUS(status) != 0)
					res = 1;
				log_debug2("parent: child %ld returned %d",
				    (long) child->pid, WEXITSTATUS(status));
			}
			
			io_close(child->io);
			io_free(child->io);
			child->io = NULL;
			
			ARRAY_REMOVE(&children, i);
			ARRAY_ADD(&dead_children, child);
			
			/*
			 * If this child was the parent of any others, kill
			 * them too.
			 */
			for (i = 0; i < ARRAY_LENGTH(&children); i++) {
				child2 = ARRAY_ITEM(&children, i);
				if (child2->parent != child)
					continue;
				
				log_debug("parent: child %ld died: killing %ld",
				    (long) child->pid, (long) child2->pid);
				kill(child2->pid, SIGTERM);
			}
		}
	}
	ARRAY_FREE(&iol);

	/* Free the dead children. */
	for (i = 0; i < ARRAY_LENGTH(&dead_children); i++) {
		child = ARRAY_ITEM(&dead_children, i);
		if (child->data != NULL)
			xfree(child->data);
		xfree(child);
	}
	ARRAY_FREE(&dead_children);

	if (sigint || sigterm) {
		act.sa_handler = SIG_IGN;
		if (sigaction(SIGINT, &act, NULL) < 0)
			fatal("sigaction failed");
		if (sigaction(SIGTERM, &act, NULL) < 0)
			fatal("sigaction failed");

		if (sigint)
			log_warnx("parent: caught SIGINT. stopping");
		else if (sigterm)
			log_warnx("parent: caught SIGTERM. stopping");

		/* Kill the children. */
		for (i = 0; i < ARRAY_LENGTH(&children); i++) {
			child = ARRAY_ITEM(&children, i);
			kill(child->pid, SIGTERM);

			io_close(child->io);
			io_free(child->io);
			xfree(child);
		}
		ARRAY_FREE(&children);

		/* And wait for them. */
		for (;;) {
			if ((pid = wait(&status)) == -1) {
				if (errno == ECHILD)
					break;
				fatal("wait failed");
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

	/* Free everything. */
	if (conf.proxy != NULL) {
		if (conf.proxy->user != NULL)
			xfree(conf.proxy->user);
		if (conf.proxy->pass != NULL)
 			xfree(conf.proxy->pass);
		if (conf.proxy->server.host != NULL)
 			xfree(conf.proxy->server.host);
		if (conf.proxy->server.port != NULL)
 			xfree(conf.proxy->server.port);
		xfree(conf.proxy);
	}
	while (!TAILQ_EMPTY(&conf.caches)) {
		cache = TAILQ_FIRST(&conf.caches);
		TAILQ_REMOVE(&conf.caches, cache, entry);
		free_cache(cache);
	}
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
	xfree(conf.def_user);
	xfree(conf.cmd_user);
	xfree(conf.user_home);
	ARRAY_FREEALL(conf.user_order);
	xfree(conf.host_name);
	if (conf.host_fqdn != NULL)
		xfree(conf.host_fqdn);
	if (conf.host_address != NULL)
		xfree(conf.host_address);
	xfree(conf.conf_file);
	xfree(conf.lock_file);
	xfree(conf.tmp_dir);
	xfree(conf.strip_chars);
	free_strings(&conf.incl);
	free_strings(&conf.excl);

	xmalloc_report(getpid(), "parent");
#endif

	exit(res);
}
