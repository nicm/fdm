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

#ifndef FDM_H
#define FDM_H

#include <sys/param.h>
#include <sys/cdefs.h>

#ifndef NO_QUEUE_H
#include <sys/queue.h>
#else
#include "compat/queue.h"
#endif

#include <dirent.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <regex.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHILDUSER	"_fdm"
#define CONFFILE	".fdm.conf"
#define SYSCONFFILE	"/etc/fdm.conf"
#define LOCKFILE	".fdm.lock"
#define SYSLOCKFILE	"/var/run/fdm.lock"
#define MAXMAILSIZE	INT_MAX
#define DEFMAILSIZE	(1 * 1024 * 1024 * 1024)	/* 1 GB */
#define DEFTIMEOUT	900
#define LOCKSLEEPTIME	2
#define MAXNAMESIZE	64
#define MAXVALUESIZE	MAXPATHLEN
#define DEFUMASK	(S_IRWXG|S_IRWXO)
#define FILEMODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define DIRMODE		(S_IRWXU|S_IRWXG|S_IRWXO)

#define NOGRP	 	((gid_t) -1)
#define NOUSR		((uid_t) -1)

extern char	*__progname;

/* Linux compatibility bullshit. */
#ifndef UID_MAX
#define UID_MAX UINT_MAX
#endif
#ifndef GID_MAX
#define GID_MAX UINT_MAX
#endif

#ifndef INFTIM
#define INFTIM -1
#endif

#ifndef __dead
#define __dead __attribute__ ((__noreturn__))
#endif
#ifndef __packed
#define __packed __attribute__ ((__packed__))
#endif

#define NFDS 64
#define COUNTFDS(s) do {						\
	int	fd_i, fd_n;						\
	fd_n = 0;							\
	for (fd_i = 0; fd_i < NFDS; fd_i++) {				\
		if (fcntl(fd_i, F_GETFL) != -1)				\
			fd_n++;						\
	}								\
	log_debug2("%s: %d file descriptors in use", s, fd_n);		\
} while (0)

/* Convert a file mode. */
#define MODE(m) \
	(m & S_IRUSR ? 4 : 0) + (m & S_IWUSR ? 2 : 0) + (m & S_IXUSR ? 1 : 0), \
    	(m & S_IRGRP ? 4 : 0) +	(m & S_IWGRP ? 2 : 0) +	(m & S_IXGRP ? 1 : 0), \
	(m & S_IROTH ? 4 : 0) +	(m & S_IWOTH ? 2 : 0) + (m & S_IXOTH ? 1 : 0)

/* Array macros. */
#define ARRAY_DECL(n, c)						\
	struct n {							\
		c	*list;						\
		u_int	 num;						\
		size_t	 space;						\
	}
#define ARRAY_INIT(a) do {						\
	(a)->num = 0;							\
	(a)->list = NULL;		 				\
	(a)->space = 0;							\
} while (0)
#define ARRAY_ADD(a, s, c) do {						\
	ENSURE_SIZE2((a)->list, (a)->space, (a)->num + 1, sizeof (c));	\
	((c *) (a)->list)[(a)->num] = s;				\
	(a)->num++;							\
} while (0)
#define ARRAY_SET(a, i, s, c) do {					\
	if (((u_int) (i)) >= (a)->num) {				\
		log_warnx("ARRAY_SET: bad index: %u, at %s:%d",		\
		    i, __FILE__, __LINE__);				\
		exit(1);						\
	}								\
	((c *) (a)->list)[i] = s;					\
} while (0)
#define ARRAY_REMOVE(a, i, c) do {					\
	if (((u_int) (i)) >= (a)->num) {				\
		log_warnx("ARRAY_REMOVE: bad index: %u, at %s:%d",	\
		    i, __FILE__, __LINE__);				\
		exit(1);						\
	}								\
	if (i < (a)->num - 1) {						\
		c 	*aptr = ((c *) (a)->list) + i;			\
		memmove(aptr, aptr + 1, (sizeof (c)) * ((a)->num - (i) - 1)); \
	}								\
	(a)->num--;							\
        if ((a)->num == 0)						\
		ARRAY_FREE(a);						\
} while (0)
#define ARRAY_EXPAND(a, n, c) do {					\
	ENSURE_SIZE2((a)->list, (a)->space, (a)->num + n, sizeof (c));	\
	(a)->num += n;							\
} while (0)
#define ARRAY_TRUNC(a, n, c) do {					\
	if ((a)->num > n)						\
		(a)->num -= n;				       		\
	else								\
		ARRAY_FREE(a);						\
} while (0)
#define ARRAY_CONCAT(a, b, c) do {					\
	ENSURE_SIZE2((a)->list, (a)->space, (a)->num + (b)->num, sizeof (c)); \
	memcpy((a)->list + (a)->num, (b)->list, (b)->num * (sizeof (c)));     \
	(a)->num += (b)->num;						\
} while (0)
#define ARRAY_EMPTY(a) ((a) == NULL || (a)->num == 0)
#define ARRAY_LENGTH(a) ((a)->num)
#define ARRAY_LAST(a, c) ARRAY_ITEM(a, (a)->num - 1, c)
#define ARRAY_ITEM(a, n, c) (((c *) (a)->list)[n])
#define ARRAY_FREE(a) do {						\
	if ((a)->list != NULL)						\
		xfree((a)->list);					\
	ARRAY_INIT(a);							\
} while (0)
#define ARRAY_FREEALL(a) do {						\
	ARRAY_FREE(a);							\
	xfree(a);							\
} while (0)

/* Definition to shut gcc up about unused arguments in a few cases. */
#define unused __attribute__ ((unused))

/* Attribute to make gcc check printf-like arguments. */
#define printflike1 __attribute__ ((format (printf, 1, 2)))
#define printflike2 __attribute__ ((format (printf, 2, 3)))
#define printflike3 __attribute__ ((format (printf, 3, 4)))
#define printflike4 __attribute__ ((format (printf, 4, 5)))

/* Ensure buffer size. */
#define ENSURE_SIZE(buf, len, size) do {				\
	(buf) = ensure_size(buf, &(len), 1, size);			\
} while (0)
#define ENSURE_SIZE2(buf, len, nmemb, size) do {			\
	(buf) = ensure_size(buf, &(len), nmemb, size);			\
} while (0)
#define ENSURE_FOR(buf, len, size, adj) do {				\
	(buf) = ensure_for(buf, &(len), size, adj);			\
} while (0)

/* Description buffer size. */
#define DESCBUFSIZE 512

/* Lengths of time. */
#define TIME_MINUTE 60LL
#define TIME_HOUR 3600LL
#define TIME_DAY 86400LL
#define TIME_WEEK 604800LL
#define TIME_MONTH 2419200LL
#define TIME_YEAR 29030400LL

/* Valid email address chars. */
#define isaddr(c) ( 							\
	((c) >= 'a' && (c) <= 'z') || 					\
	((c) >= 'A' && (c) <= 'Z') ||					\
	((c) >= '0' && (c) <= '9') ||					\
	(c) == '&' || (c) == '*' || (c) == '+' || (c) == '?' ||	 	\
	(c) == '-' || (c) == '.' || (c) == '=' || (c) == '/' ||		\
	(c) == '^' || (c) == '{' || (c) == '}' || (c) == '~' || 	\
	(c) == '_' || (c) == '@' || (c) == '\'')

/* Number of matches to use. */
#define NPMATCH 10

/* Account name match. */
#define name_match(p, n) (fnmatch(p, n, 0) == 0)

/* Macros in configuration file. */
struct macro {
	char			 name[MAXNAMESIZE];
	union {
		long long	 num;
		char		*str;
	} value;
	enum {
		MACRO_NUMBER,
		MACRO_STRING
	} type;

	TAILQ_ENTRY(macro)	entry;
};
TAILQ_HEAD(macros, macro);

/* Valid macro name chars. */
#define ismacrofirst(c) (						\
	((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
#define ismacro(c) (							\
	((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z') ||	\
	((c) >= '0' && (c) <= '9') || (c) == '_' || (c) == '-')

/* Command-line commands. */
enum fdmop {
	FDMOP_NONE = 0,
	FDMOP_POLL,
	FDMOP_FETCH
};

/* Server description. */
struct server {
	char		*host;
	char		*port;
	struct addrinfo	*ai;
	int		 ssl;
};

/* Proxy type. */
enum proxytype {
	PROXY_HTTP,
	PROXY_HTTPS,
	PROXY_SOCKS5
};

/* Proxy definition. */
struct proxy {
	enum proxytype	 type;
	char		*user;
	char		*pass;
	struct server	 server;
};

/* Shared memory. */
struct shm {
	char	 name[MAXPATHLEN];
	int	 fd;

	void	*data;
	size_t	 size;
};

/* Generic array of strings. */
ARRAY_DECL(strings, char *);

/* Options for final mail handling. */
enum decision {
	DECISION_NONE,
	DECISION_DROP,
	DECISION_KEEP
};

/* A mail tag. */
struct tag {
	char	name[MAXNAMESIZE];
	char	value[MAXVALUESIZE];
};

/* Array of tags. */
ARRAY_DECL(tags, struct tag);

/* A single mail. */
struct mail {
	struct tags		 tags;

	struct shm		 shm;

	struct attach		*attach;

	char			*base;

	char			*data;
	size_t			 off;

	size_t	 	 	 size;		/* size of mail */
	size_t	 	 	 space;		/* size of malloc'd area */

	ARRAY_DECL(, size_t *)	 wrapped;	/* list of wrapped lines */

	ssize_t		 	 body;		/* offset of body */
};

/* An attachment. */
struct attach {
	u_int	 	 	 idx;

	size_t		 	 data;
	size_t	 	 	 body;
	size_t   	 	 size;

	char			*type;
	char			*name;

	struct attach		*parent;
	TAILQ_HEAD(, attach)	 children;

	TAILQ_ENTRY(attach)	 entry;
};

/* Regexp wrapper struct. */
struct re {
	char		*str;
	regex_t		 re;
};

/* A single child. */
struct child {
	pid_t		 pid;
	struct io	*io;
	struct account	*account;
};

/* List of children. */
ARRAY_DECL(children, struct child *);

/* Account entry. */
struct account {
	char			 name[MAXNAMESIZE];

	struct strings		*users;
	int			 find_uid;

	int			 disabled;
	int			 keep;

	struct fetch		*fetch;
	void			*data;

	TAILQ_ENTRY(account)	 entry;
};

/* Action definition. */
struct action {
	char			 name[MAXNAMESIZE];

	struct strings		*users;
	int			 find_uid;

	struct deliver		*deliver;
	void			*data;

	TAILQ_ENTRY(action)	 entry;
};

/* Actions arrays. */
ARRAY_DECL(actions, struct action *);

/* Match areas. */
enum area {
	AREA_BODY,
	AREA_HEADERS,
	AREA_ANY
};

/* Expression operators. */
enum exprop {
	OP_NONE,
	OP_AND,
	OP_OR
};

/* Expression item. */
struct expritem {
	struct match		*match;
	void			*data;

	enum exprop		 op;
	int			 inverted;

	TAILQ_ENTRY(expritem)	 entry;
};

/* Expression struct. */
TAILQ_HEAD(expr, expritem);

/* Rule list. */
TAILQ_HEAD(rules, rule);

/* Rule types. */
enum ruletype {
	RULE_EXPRESSION,
	RULE_ALL
};

/* Rule entry. */
struct rule {
	u_int			 idx;
	enum ruletype		 type;

	struct strings		*accounts;
	struct expr		*expr;

	struct strings		*users;
	int			 find_uid;	/* find uids from headers */

	int			 stop;		/* stop matching at this rule */

	struct tag		 tag;

	struct rules		 rules;
	struct strings		*actions;

	TAILQ_ENTRY(rule)	 entry;
};

/* Lock types. */
#define LOCK_FCNTL 0x1
#define LOCK_FLOCK 0x2
#define LOCK_DOTLOCK 0x4

/* Configuration settings. */
struct conf {
	int 			 debug;
	int			 syslog;

	uid_t			 child_uid;
	gid_t			 child_gid;
	const char		*tmp_dir;

	struct strings	 	 incl;
	struct strings		 excl;

	struct proxy		*proxy;

	struct strings		*domains; /* domains to look for with users */
	struct strings		*headers; /* headers to search for users */

	struct {
		int		 valid;
		uid_t		 last_uid;

		char		*home;
		char		*user;
		char		*uid;
		char		*host;
		char		*fqdn;
		char		*addr;
	} info;

	char			*conf_file;
	char			*lock_file;
	int			 check_only;
	int			 allow_many;
	int			 keep_all;
	int			 no_received;
	u_int			 purge_after;
	enum decision		 impl_act;

	mode_t			 file_umask;
	gid_t			 file_group;

	size_t			 max_size;
	int			 timeout;
	int		         del_big;
	u_int			 lock_types;
	uid_t			 def_user;

	TAILQ_HEAD(, account)	 accounts;
 	TAILQ_HEAD(, action)	 actions;
	struct rules		 rules;
};
extern struct conf		 conf;

/* Shorthand for the ridiculous call to get the SSL error. */
#define SSL_err() (ERR_error_string(ERR_get_error(), NULL))

/* Limits at which to fail. */
#define IO_MAXLINELEN (1024 * 1024) 		/* 1 MB */
#define IO_MAXBUFFERLEN (1024 * 1024 * 1024) 	/* 1 GB */

/* IO line endings. */
#define IO_CRLF "\r\n"
#define IO_CR   "\r"
#define IO_LF   "\n"

/* Amount to attempt to append to the buffer each time. */
#define IO_BLOCKSIZE 16384

/* Initial line buffer length. */
#define IO_LINESIZE 256

/* Amount to poll after in io_update. */
#define IO_FLUSHSIZE (2 * IO_BLOCKSIZE)

/* Maximum number of pollfds. */
#define IO_POLLFDS 64

/* IO buffer size macros. */
#define IO_ROUND(n) (((n / IO_BLOCKSIZE) + 1) * IO_BLOCKSIZE)
#define IO_RDSIZE(io) ((io)->rsize)
#define IO_WRSIZE(io) ((io)->wsize)

/* IO structure. */
struct io {
	int		 fd;
	int		 dup_fd;	/* dup all data to this fd */
	SSL		*ssl;

	int		 closed;
	char		*error;

	int		 flags;
#define IO_RD 0x1
#define IO_WR 0x2
#define IO_NEEDFILL 0x4
#define IO_NEEDPUSH 0x8
#define IO_FIXED 0x10			/* fixed write buffer */

	char		*rbase;		/* buffer start */
	size_t		 rspace;	/* total size of buffer */
	size_t		 rsize;		/* amount of data available */
	size_t		 roff;		/* base of data in buffer */

	char		*wbase;		/* buffer start */
	size_t		 wspace;	/* total size of buffer */
	size_t		 wsize;		/* size of data currently in buffer */
	size_t		 woff;

	char		*lbuf;		/* line buffer */
	size_t		 llen;		/* line buffer size */

	int		 timeout;
	const char	*eol;
};

/* Command flags. */
#define CMD_IN  0x1
#define CMD_OUT 0x2
#define CMD_ONCE 0x4

/* Command data. */
struct cmd {
	pid_t	 	 pid;
	int		 status;
	int		 flags;

	struct io	*io_in;
	struct io	*io_out;
	struct io	*io_err;
};

/* Poll return codes. */
#define POLL_SUCCESS FETCH_SUCCESS
#define POLL_ERROR FETCH_ERROR

/* Fetch return codes. */
#define FETCH_SUCCESS 0
#define FETCH_ERROR 1
#define FETCH_OVERSIZE 2
#define FETCH_COMPLETE 3

/* Fetch functions. */
struct fetch {
	const char	*ports[2];	/* normal port, ssl port */

	int		 (*init)(struct account *);
	int	 	 (*connect)(struct account *);
	int 		 (*poll)(struct account *, u_int *);
	int	 	 (*fetch)(struct account *, struct mail *);
	int		 (*purge)(struct account *);
	int		 (*delete)(struct account *);
	int		 (*keep)(struct account *);
	int		 (*disconnect)(struct account *);
	int		 (*free)(struct account *);
	void		 (*desc)(struct account *, char *, size_t);
};

/* Deliver context. */
struct deliver_ctx {
	struct account	*account;
	struct mail	*mail;

	struct mail	 wr_mail;

	enum decision	*decision;

	int		*pm_valid;
	regmatch_t	 pm[NPMATCH];
};

/* Deliver return codes. */
#define DELIVER_SUCCESS 0
#define DELIVER_FAILURE 1

/* Delivery types. */
enum delivertype {
	DELIVER_INCHILD,	/* do not pass up to parent */
	DELIVER_ASUSER,		/* do pass up to parent to drop privs */
	DELIVER_WRBACK		/* modifies mail: pass up to parent and expect
				   a new mail back */
};

/* Deliver functions. */
struct deliver {
	enum delivertype type;

	int	 	 (*deliver)(struct deliver_ctx *, struct action *);
	void		 (*desc)(struct action *, char *, size_t);
};

#define MATCH_FALSE 0
#define MATCH_TRUE 1
#define MATCH_ERROR 2

/* Match context. */
struct match_ctx {
	struct io	*io;
	struct account	*account;
	struct mail     *mail;

	enum decision	 decision;

	int		 matched;
	int		 stopped;

	int		 pm_valid;
	regmatch_t	 pm[NPMATCH];
};

/* Match functions. */
struct match {
	int		 (*match)(struct match_ctx *, struct expritem *);
	void 		 (*desc)(struct expritem *, char *, size_t);
};

/* Privsep message types. */
enum msgtype {
	MSG_ACTION,
	MSG_EXIT,
	MSG_DONE,
	MSG_COMMAND
};

/* Privsep message data. */
struct msgdata {
	int	 	 	 error;
	struct mail	 	 mail;

	int		 	 pm_valid;
	regmatch_t	 	 pm[NPMATCH];

	/* these only work so long as they aren't moved in either process */
	struct account		*account;
	struct action		*action;
	struct command_data	*cmddata;

	uid_t		 	 uid;
};

/* Privsep message. */
struct msg {
	u_int		 n;

	enum msgtype	 type;
	size_t		 size;

	struct msgdata	 data;
};

/* Comparison operators. */
enum cmp {
	CMP_EQ,
	CMP_NE,
	CMP_LT,
	CMP_GT
};

/* Match attachment data. */
struct attachment_data {
	enum {
		ATTACHOP_COUNT,
		ATTACHOP_TOTALSIZE,
		ATTACHOP_ANYSIZE,
		ATTACHOP_ANYTYPE,
		ATTACHOP_ANYNAME
	} op;

	enum cmp	 	 cmp;
	union {
		size_t		 size;
		long long	 num;
		char		*str;
		struct re	 re;
	} value;
};

/* Match age data. */
struct age_data {
	long long	 time;
	enum cmp	 cmp;
};

/* Match size data. */
struct size_data {
	size_t		 size;
	enum cmp	 cmp;
};

/* Match tagged data. */
struct tagged_data {
	char		*tag;
};

/* Match string data. */
struct string_data {
	struct re	 re;

	char		*str;
};

/* Match regexp data. */
struct regexp_data {
	struct re	 re;

	enum area 	 area;
};

/* Match command data. */
struct command_data {
	char		*cmd;
	uid_t		 uid;
	int		 pipe;		/* pipe mail to command */

	struct re	 re;		/* re->re NULL to not check */
	int		 ret;		/* -1 to not check */
};

/* Fetch maildir data. */
struct maildir_data {
	struct strings	*maildirs;

	struct strings	*paths;
	u_int		 index;

	DIR		*dirp;
	char		*path;
	char		 entry[MAXPATHLEN];
};

/* NNTP group entry. */
struct nntp_group {
	char		*name;
	int		 ignore;

	u_int		 size;
	u_int		 last;
	char		*id;
};

/* NNTP group list. */
ARRAY_DECL(nntp_groups, struct nntp_group *);

/* Fetch nntp data. */
struct nntp_data {
	char		*path;

	struct server	 server;
	struct strings	*names;

	u_int		 group;
	struct nntp_groups groups;

	struct io	*io;
};
#define GET_GROUP(d, i) ARRAY_ITEM(&d->groups, i, struct nntp_group *)
#define CURRENT_GROUP(d) GET_GROUP(d, d->group)
#define TOTAL_GROUPS(d) ARRAY_LENGTH(&d->groups)
#define ADD_GROUP(d, g) ARRAY_ADD(&d->groups, g, struct nntp_group *)

/* Fetch stdin data. */
struct stdin_data {
	int		 complete;

	struct io	*io;
};

/* Fetch pop3 data. */
struct pop3_data {
	char		*user;
	char		*pass;

	struct server	 server;

	u_int		 cur;
	u_int		 num;

	char		*uid;
	struct strings	 kept;

	struct io	*io;
};

/* IMAP tag types. */
#define IMAP_TAG_NONE -1
#define IMAP_TAG_CONTINUE -2
#define IMAP_TAG_ERROR -3

/* IMAP line types. */
#define IMAP_TAGGED 0
#define IMAP_CONTINUE 1
#define IMAP_UNTAGGED 2
#define IMAP_RAW 3

/* Fetch imap data. */
struct imap_data {
	struct server	 server;
	char		*pipecmd;

	struct io	*io;
	struct cmd	*cmd;

	char		*user;
	char		*pass;
	char		*folder;

	int		 tag;
	u_int		 cur;
	u_int		 num;

	u_int	 	 uid;
	ARRAY_DECL(, u_int) kept;

	char		*src;

	size_t		 llen;
	char		*lbuf;

	char		*(*getln)(struct account *a, int);
	int		 (*putln)(struct account *a, const char *, ...);
	void		 (*flush)(struct account *a);
};

/* Deliver smtp states. */
enum smtp_state {
	SMTP_CONNECTING,
	SMTP_HELO,
	SMTP_FROM,
	SMTP_TO,
	SMTP_DATA,
	SMTP_DONE,
	SMTP_QUIT
};

/* Deliver smtp data. */
struct smtp_data {
	struct server	 server;
	char		*to;
};

/* Deliver mbox data. */
struct mbox_data {
	char		*path;
	int		 compress;
};

/* Deliver stdout data. */
struct stdout_data {
	int		 add_from;
};

/* match-age.c */
extern struct match	 match_age;

/* match-attachment.c */
extern struct match	 match_attachment;

/* match-matched.c */
extern struct match	 match_matched;

/* match-unmatched.c */
extern struct match	 match_unmatched;

/* match-size.c */
extern struct match	 match_size;

/* match-tagged.c */
extern struct match	 match_tagged;

/* match-string.c */
extern struct match	 match_string;

/* match-command.c */
extern struct match	 match_command;

/* match-regexp.c */
extern struct match	 match_regexp;

/* fetch-maildir.c */
extern struct fetch 	 fetch_maildir;

/* fetch-stdin.c */
extern struct fetch 	 fetch_stdin;

/* fetch-nntp.c */
extern struct fetch 	 fetch_nntp;

/* fetch-pop3.c */
extern struct fetch 	 fetch_pop3;

/* fetch-imap.c */
extern struct fetch 	 fetch_imap;

/* fetch-imappipe.c */
extern struct fetch 	 fetch_imappipe;

/* deliver-smtp.c */
extern struct deliver	 deliver_smtp;

/* deliver-smtp.c */
extern struct deliver	 deliver_stdout;

/* deliver-pipe.c */
extern struct deliver 	 deliver_pipe;

/* deliver-drop.c */
extern struct deliver 	 deliver_drop;

/* deliver-keep.c */
extern struct deliver 	 deliver_keep;

/* deliver-maildir.c */
extern struct deliver 	 deliver_maildir;

/* deliver-remove-header.c */
extern struct deliver	 deliver_remove_header;

/* deliver-append-string.c */
extern struct deliver	 deliver_append_string;

/* deliver-mbox.c */
extern struct deliver 	 deliver_mbox;

/* deliver-write.c */
extern struct deliver 	 deliver_write;
int	 		 do_write(struct deliver_ctx *, struct action *, int);

/* deliver-append.c */
extern struct deliver 	 deliver_append;

/* deliver-rewrite.c */
extern struct deliver 	 deliver_rewrite;

#ifdef NO_SETRESUID
#define setresuid(r, e, s) setreuid(r, e)
#endif

#ifdef NO_SETRESGID
#define setresgid(r, e, s) setregid(r, e)
#endif

#ifdef NO_STRTONUM
/* strtonum.c */
long long		 strtonum(const char *, long long, long long,
			     const char **);
#endif

#ifdef NO_STRLCPY
/* strlcpy.c */
size_t	 		 strlcpy(char *, const char *, size_t);
#endif

#ifdef NO_STRLCAT
/* strlcat.c */
size_t	 		 strlcat(char *, const char *, size_t);
#endif

#ifdef NO_ASPRINTF
/* asprintf.c */
int			 asprintf(char **, const char *, ...);
int			 vasprintf(char **, const char *, va_list);
#endif

/* shm.c */
void 			*shm_reopen(struct shm *);
void			*shm_malloc(struct shm *, size_t);
void			*shm_realloc(struct shm *, size_t, size_t);
void			 shm_free(struct shm *);
void			 shm_destroy(struct shm *);

/* parse.y */
extern struct macros	 macros;
struct strings 		*weed_strings(struct strings *);
char 			*fmt_strings(const char *, struct strings *);
struct macro		*find_macro(char *);
struct actions		*match_actions(char *);

/* fdm.c */
double			 get_time(void);
int			 dropto(uid_t);
int			 check_incl(char *);
int		         check_excl(char *);
int			 use_account(struct account *, char **);
void			 fill_info(const char *);
void			 fill_fqdn(char *, char **, char **);

/* imap-common.c */
int			 imap_tag(char *);
int			 imap_init(struct account *);
int			 imap_free(struct account *);
int			 imap_login(struct account *);
int			 imap_select(struct account *);
int			 imap_close(struct account *);
int			 imap_logout(struct account *);
void			 imap_abort(struct account *);
int			 imap_uid(struct account *);
int			 imap_poll(struct account *, u_int *);
int			 imap_fetch(struct account *, struct mail *);
int			 imap_purge(struct account *);
int			 imap_delete(struct account *);
int	 		 imap_keep(struct account *);

/* re.c */
int			 re_compile(struct re *, char *, int, char **);
int			 re_execute(struct re *, char *, int, regmatch_t *,
			     int, char **);
int			 re_simple(struct re *, char *, char **);

/* attach.c */
struct attach 		*attach_visit(struct attach *, u_int *);
void printflike2	 attach_log(struct attach *, const char *, ...);
struct attach 		*attach_build(struct mail *);
void			 attach_free(struct attach *);

/* privsep.c */
int			 privsep_send(struct io *, struct msg *, void *,
			     size_t);
int			 privsep_check(struct io *);
int			 privsep_recv(struct io *, struct msg *, void **,
			     size_t *);

/* command.c */
struct cmd 		*cmd_start(const char *, int, char *, size_t, char **);
int			 cmd_poll(struct cmd *, char **, char **, char **,
			     size_t *, char **);
void			 cmd_free(struct cmd *);

/* child.c */
int			 child_fork(void);
__dead void		 child_exit(int);
int			 do_child(int, enum fdmop, struct account *);

/* parent.c */
int			 do_parent(struct child *);

/* connect.c */
struct proxy 		*getproxy(const char *);
struct io 		*connectproxy(struct server *, struct proxy *,
			     const char *, int, char **);
struct io		*connectio(struct server *, const char *, int, char **);

/* mail.c */
void			 mail_open(struct mail *, size_t);
void			 mail_send(struct mail *, struct msg *);
void			 mail_receive(struct mail *, struct msg *);
void			 mail_reopen(struct mail *, char *);
void			 mail_close(struct mail *);
void			 mail_destroy(struct mail *);
void			 resize_mail(struct mail *, size_t);
char 			*rfc822_time(time_t, char *, size_t);
int 			 printpath(char *, size_t, const char *, ...);
int			 openlock(char *, u_int, int, mode_t);
void			 closelock(int, char *, u_int);
int			 checkperms(char *, char *, int *);
void			 line_init(struct mail *, char **, size_t *);
void			 line_next(struct mail *, char **, size_t *);
int			 insert_header(struct mail *, const char *,
			     const char *, ...);
int			 remove_header(struct mail *, const char *);
char 			*find_header(struct mail *, const char *, size_t *,
			     int);
struct strings		*find_users(struct mail *);
char			*find_address(char *, size_t, size_t *);
void			 trim_from(struct mail *);
char 		        *make_from(struct mail *);
u_int			 fill_wrapped(struct mail *);
void			 set_wrapped(struct mail *, char);

/* cleanup.c */
void			 cleanup_check(void);
void			 cleanup_flush(void);
void			 cleanup_purge(void);
void			 cleanup_register(char *);
void			 cleanup_deregister(char *);

/* replace.c */
void printflike3	 add_tag(struct tags *, const char *, const char *,
			     ...);
struct tag 		*find_tag(struct tags *, const char *);
struct tag 		*match_tag(struct tags *, const char *);
void			 default_tags(struct tags *, char *, struct account *);
void			 update_tags(struct tags *);
char 			*replace(const char *, struct tags *, struct mail *, 
    			     int, regmatch_t [NPMATCH]);

/* io.c */
struct io		*io_create(int, SSL *, const char *, int);
void			 io_free(struct io *);
void			 io_close(struct io *);
int			 io_update(struct io *, char **);
int			 io_polln(struct io **, u_int, struct io **, int,
			     char **);
int			 io_poll(struct io *, char **);
int			 io_read2(struct io *, void *, size_t);
void 			*io_read(struct io *, size_t);
void			 io_writefixed(struct io *, void *, size_t);
void			 io_write(struct io *, const void *, size_t);
char 			*io_readline2(struct io *, char **, size_t *);
char 			*io_readline(struct io *);
void printflike2	 io_writeline(struct io *, const char *, ...);
void			 io_vwriteline(struct io *, const char *, va_list);
int			 io_pollline(struct io *, char **, char **);
int			 io_pollline2(struct io *, char **, char **, size_t *,
			     char **);
int			 io_flush(struct io *, char **);
int			 io_wait(struct io *, size_t, char **);

/* log.c */
void			 log_init(int);
void		    	 vlog(int, const char *, va_list);
void printflike1	 log_warn(const char *, ...);
void printflike1	 log_warnx(const char *, ...);
void printflike1	 log_info(const char *, ...);
void printflike1	 log_debug(const char *, ...);
void printflike1	 log_debug2(const char *, ...);
void printflike1	 log_debug3(const char *, ...);
__dead void		 fatal(const char *);
__dead void		 fatalx(const char *);

/* xmalloc.c */
void		*ensure_size(void *, size_t *, size_t, size_t);
void		*ensure_for(void *, size_t *, size_t, size_t);
char		*xstrdup(const char *);
void		*xxcalloc(size_t, size_t);
void		*xxmalloc(size_t);
void		*xxrealloc(void *, size_t, size_t);
void		 xxfree(void *);
int printflike2	 xxasprintf(char **, const char *, ...);
int		 xxvasprintf(char **, const char *, va_list);
int printflike3	 xsnprintf(char *, size_t, const char *, ...);
int		 xvsnprintf(char *, size_t, const char *, va_list);

/* xmalloc-debug.c */
#ifdef DEBUG
void		 xmalloc_callreport(const char *);

void		 xmalloc_clear(void);
void		 xmalloc_report(const char *);

void		*dxmalloc(const char *, u_int, size_t);
void		*dxcalloc(const char *, u_int, size_t, size_t);
void		*dxrealloc(const char *, u_int, void *, size_t, size_t);
void		 dxfree(const char *, u_int, void *);
int printflike4	 dxasprintf(const char *, u_int, char **, const char *, ...);
int		 dxvasprintf(const char *, u_int, char **, const char *,
		     va_list);
#endif

#ifdef DEBUG
#define xmalloc(s) dxmalloc(__FILE__, __LINE__, s)
#define xcalloc(n, s) dxcalloc(__FILE__, __LINE__, n, s)
#define xrealloc(p, n, s) dxrealloc(__FILE__, __LINE__, p, n, s)
#define xfree(p) dxfree(__FILE__, __LINE__, p)
#define xasprintf(pp, ...) dxasprintf(__FILE__, __LINE__, pp, __VA_ARGS__)
#define xvasprintf(pp, fmt, ap) dxvasprintf(__FILE__, __LINE__, pp, fmt, ap)
#else
#define xmalloc(s) xxmalloc(s)
#define xcalloc(n, s) xxcalloc(n, s)
#define xrealloc(p, n, s) xxrealloc(p, n, s)
#define xfree(p) xxfree(p)
#define xasprintf(pp, ...) xxasprintf(pp, __VA_ARGS__)
#define xvasprintf(pp, fmt, ap) xxvasprintf(pp, fmt, ap)
#endif

#endif /* FDM_H */
