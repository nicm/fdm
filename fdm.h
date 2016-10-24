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

#ifndef FDM_H
#define FDM_H

#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/stat.h>

#ifdef HAVE_QUEUE_H
#include <sys/queue.h>
#else
#include "compat/queue.h"
#endif

#ifdef HAVE_TREE_H
#include <sys/tree.h>
#else
#include "compat/tree.h"
#endif

#include <dirent.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#ifndef _PUBLIC_
#define _PUBLIC_
#endif
#include <tdb.h>
#include <regex.h>

#ifdef PCRE
#include <pcre.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHILDUSER	"_fdm"
#define CONFFILE	".fdm.conf"
#define LOCKFILE	".fdm.lock"
#define DEFLOCKTIMEOUT	10
#define MAXQUEUEVALUE	50
#define DEFMAILQUEUE	2
#define DEFMAILSIZE	(32 * 1024 * 1024)		/* 32 MB */
#define MAXMAILSIZE	(1 * 1024 * 1024 * 1024)	/*  1 GB */
#define DEFSTRIPCHARS	"\\<>$%^&*|{}[]\"'`;"
#define MAXACTIONCHAIN	5
#define DEFTIMEOUT	(900 * 1000)
#define LOCKSLEEPTIME	10000				/* 0.1 seconds */
#define MAXNAMESIZE	64
#define DEFUMASK	(S_IRWXG|S_IRWXO)
#define FILEMODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define DIRMODE		(S_IRWXU|S_IRWXG|S_IRWXO)
#define MAXUSERLEN	256

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

/* Databases are not portable between endiness on OSs without these. */
#ifndef htole64
#define htole64
#endif
#ifndef letoh64
#define letoh64
#endif

/* Fatal errors. */
#define fatal(msg) log_fatal("%s: %s", __func__, msg);
#define fatalx(msg) log_fatalx("%s: %s", __func__, msg);

/* Apply umask. */
#define UMASK(mask) ((mask) & ~conf.file_umask)

/* Convert a file mode for %o%o%o printf. */
#define MODE(m) \
	(m & S_IRUSR ? 4 : 0) + (m & S_IWUSR ? 2 : 0) + (m & S_IXUSR ? 1 : 0), \
	(m & S_IRGRP ? 4 : 0) +	(m & S_IWGRP ? 2 : 0) +	(m & S_IXGRP ? 1 : 0), \
	(m & S_IROTH ? 4 : 0) +	(m & S_IWOTH ? 2 : 0) + (m & S_IXOTH ? 1 : 0)

/* Definition to shut gcc up about unused arguments. */
#define unused __attribute__ ((unused))

/* Attribute to make gcc check printf-like arguments. */
#define printflike1 __attribute__ ((format (printf, 1, 2)))
#define printflike2 __attribute__ ((format (printf, 2, 3)))
#define printflike3 __attribute__ ((format (printf, 3, 4)))
#define printflike4 __attribute__ ((format (printf, 4, 5)))
#define printflike5 __attribute__ ((format (printf, 5, 6)))
#define printflike6 __attribute__ ((format (printf, 6, 7)))

/* Ensure buffer size. */
#define ENSURE_SIZE(buf, len, size) do {				\
	(buf) = ensure_size(buf, &(len), 1, size);			\
} while (0)
#define ENSURE_FOR(buf, len, size, adj) do {				\
	(buf) = ensure_for(buf, &(len), size, adj);			\
} while (0)

/* Description buffer size. */
#define DESCBUFSIZE 512

/* Replace buffer size. */
#define REPLBUFSIZE 64

/* Lengths of time. */
#define TIME_MINUTE 60LL
#define TIME_HOUR 3600LL
#define TIME_DAY 86400LL
#define TIME_WEEK 604800LL
#define TIME_MONTH 2419200LL
#define TIME_YEAR 29030400LL

/* Number of matches to use. */
#define NPMATCH 10

/* Account and action name match. */
#define account_match(p, n) (fnmatch(p, n, 0) == 0)
#define action_match(p, n) (fnmatch(p, n, 0) == 0)

#include "array.h"
#include "io.h"

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

	TAILQ_ENTRY(macro)	 entry;
};
TAILQ_HEAD(macros, macro);

/* Command-line commands. */
enum fdmop {
	FDMOP_NONE = 0,
	FDMOP_POLL,
	FDMOP_FETCH,
	FDMOP_CACHE
};

/*
 * Wrapper struct for a string that needs tag replacement before it is used.
 * This is used for anything that needs to be replaced after account and mail
 * data are available, everything else is replaced at parse time.
 */
struct replstr {
	char		*str;
} __packed;
ARRAY_DECL(replstrs, struct replstr);

/* Similar to replstr but needs expand_path too. */
struct replpath {
	char		*str;
} __packed;

/* Server description. */
struct server {
	char		*host;
	char		*port;
	struct addrinfo	*ai;
	int		 ssl;
	int		 verify;
	int		 insecure;
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
	char	 name[MAXNAMLEN];
	int	 fd;
#define SHM_REGISTER(shm) cleanup_register(shm_path(shm))
#define SHM_DEREGISTER(shm) cleanup_deregister(shm_path(shm))

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

/* String block entry. */
struct strbent {
	size_t	key;
	size_t	value;
};

/* String block header. */
struct strb {
	u_int		 ent_used;
	u_int		 ent_max;

	size_t		 str_used;
	size_t		 str_size;
};

/* Initial string block slots and block size. */
#define STRBOFFSET (((sizeof (struct strb)) + 0x3f) & ~0x3f)
#define STRBENTRIES 64
#define STRBBLOCK 1024

/* String block access macros. */
#define STRB_BASE(sb) (((char *) (sb)) + STRBOFFSET)

#define STRB_KEY(sb, sbe) (STRB_BASE(sb) + (sbe)->key)
#define STRB_VALUE(sb, sbe) (STRB_BASE(sb) + (sbe)->value)

#define STRB_ENTBASE(sb) (STRB_BASE(sb) + (sb)->str_size)
#define STRB_ENTOFF(sb, n) ((n) * (sizeof (struct strbent)))
#define STRB_ENTSIZE(sb) STRB_ENTOFF(sb, (sb)->ent_max)

#define STRB_ENTRY(sb, n) ((void *) (STRB_ENTBASE(sb) + STRB_ENTOFF(sb, n)))
#define STRB_SIZE(sb) (STRBOFFSET + (sb)->str_size + STRB_ENTSIZE((sb)))

/* Regexp wrapper structs. */
struct re {
	char		*str;
#ifndef PCRE
	regex_t		 re;
#else
	pcre		*pcre;
#endif
	int		 flags;
};

struct rm {
	int		 valid;

	size_t		 so;
	size_t		 eo;
};

struct rmlist {
	int		 valid;

	struct rm	 list[NPMATCH];
};

/* Regexp flags. */
#define RE_IGNCASE 0x1
#define RE_NOSUBST 0x2

/* Cache data. */
struct cache {
	TDB_CONTEXT		*db;

	char			*path;
	uint64_t		 expire;

	TAILQ_ENTRY(cache)	 entry;
};
struct cacheitem {
	uint64_t		 tim;
	uint32_t		 pad[4];
} __packed;

/* A single mail. */
struct mail {
	u_int			 idx;
	double			 tim;

	struct strb		*tags;

	struct shm		 shm;

	struct attach		*attach;
	int			 attach_built;

	char			*base;

	char			*data;
	size_t			 off;

	size_t			 size;		/* size of mail */
	size_t			 space;		/* size of allocated area */

	size_t			 body;		/* offset of body */

	ARRAY_DECL(, size_t)	 wrapped;	/* list of wrapped lines */
	char			 wrapchar;	/* wrapped character */

	/* XXX move below into special struct and just cp it in mail_*? */
	struct rmlist		 rml;		/* regexp matches */

	enum decision		 decision;	/* final deliver decision */

	void			 (*auxfree)(void *);
	void			*auxdata;
};

/* Mail match/delivery return codes. */
#define MAIL_CONTINUE 0
#define MAIL_DELIVER 1
#define MAIL_MATCH 2
#define MAIL_ERROR 3
#define MAIL_BLOCKED 4
#define MAIL_DONE 5

/* Mail match/delivery context. */
struct mail_ctx {
	int				 done;
	u_int				 msgid;

	struct account			*account;
	struct io			*io;
	struct mail			*mail;

	u_int				 ruleidx;
	struct rule			*rule;
	ARRAY_DECL(, struct rule *)	 stack;
	struct expritem			*expritem;
	int				 result;
	int				 matched;

	TAILQ_HEAD(, deliver_ctx)	 dqueue;

	TAILQ_ENTRY(mail_ctx)		 entry;
};
TAILQ_HEAD(mail_queue, mail_ctx);

/* An attachment. */
struct attach {
	u_int			 idx;

	size_t			 data;
	size_t			 body;
	size_t			 size;

	char			*type;
	char			*name;

	struct attach		*parent;
	TAILQ_HEAD(, attach)	 children;

	TAILQ_ENTRY(attach)	 entry;
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
	int				 error;
	struct mail			 mail;

	/* These only work so long as they aren't moved in either process. */
	struct account			*account;
	struct actitem			*actitem;
	struct match_command_data	*cmddata;

	uid_t				 uid;
	gid_t				 gid;
};

/* Privsep message buffer. */
struct msgbuf {
	void		*buf;
	size_t		 len;
};

/* Privsep message. */
struct msg {
	u_int		 id;
	enum msgtype	 type;
	size_t		 size;

	struct msgdata	 data;
};

/* A single child. */
struct child {
	pid_t		 pid;
	struct child	*parent;
	struct io	*io;

	void		*data;
	int		 (*msg)(struct child *, struct msg *, struct msgbuf *);

	void		*buf;
	size_t		 len;
};

/* List of children. */
ARRAY_DECL(children, struct child *);

/* Fetch child data. */
struct child_fetch_data {
	struct account	*account;
	enum fdmop	 op;
	struct children	*children;
};

/* Deliver child data. */
struct child_deliver_data {
	void			 (*hook)(int, struct account *, struct msg *,
				      struct child_deliver_data *, int *);

	struct child		*child; /* the source of the request */

	uid_t			 uid;
	gid_t			 gid;

	u_int			 msgid;
	const char		*name;

	struct account		*account;
	struct mail		*mail;
	struct actitem		*actitem;

	struct deliver_ctx	*dctx;
	struct mail_ctx		*mctx;

	struct match_command_data *cmddata;
};

/* Account entry. */
struct account {
	u_int			 idx;

	char			 name[MAXNAMESIZE];

	struct replstrs		*users;

	int			 disabled;
	int			 keep;

	struct fetch		*fetch;
	void			*data;

	TAILQ_ENTRY(account)	 entry;
	TAILQ_ENTRY(account)	 active_entry;
};

/* Action item. */
struct actitem {
	u_int			 idx;

	struct deliver		*deliver;
	void			*data;

	TAILQ_ENTRY(actitem)	 entry;
};

/* Action list. */
TAILQ_HEAD(actlist, actitem);

/* Action definition. */
struct action {
	char			 name[MAXNAMESIZE];

	struct replstrs		*users;

	struct actlist		*list;

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

/* Rule entry. */
struct rule {
	u_int			 idx;

	struct expr		*expr;

	struct replstrs		*users;

	int			 stop;		/* stop matching at this rule */

	struct rules		 rules;
	struct action		*lambda;
	struct replstrs		*actions;

	TAILQ_ENTRY(rule)	 entry;
};

/* Lock types. */
#define LOCK_FCNTL 0x1
#define LOCK_FLOCK 0x2
#define LOCK_DOTLOCK 0x4

/* User info settings. */
struct userdata {
	char	*name;
	char	*home;

	uid_t	 uid;
	gid_t	 gid;
};

/* User lookup order. */
typedef struct userdata *(*userfunction)(const char *);
ARRAY_DECL(userfunctions, userfunction);

/* Configuration settings. */
struct conf {
	int			 debug;
	int			 syslog;

	uid_t			 child_uid;
	gid_t			 child_gid;
	char			*tmp_dir;

	struct strings		 incl;
	struct strings		 excl;

	struct proxy		*proxy;

	char			*user_home;
	struct userfunctions	*user_order;

	char			*host_name;
	char			*host_fqdn;
	char			*host_address;

	char			*conf_file;
	char			*strip_chars;
	int			 check_only;
	int			 allow_many;
	int			 keep_all;
	int			 no_received;
	int			 no_create;
	int			 verify_certs;
	u_int			 purge_after;
	enum decision		 impl_act;
	int			 max_accts;

	char			*lock_file;
	int			 lock_wait;
	int			 lock_timeout;

	int			 queue_high;
	int			 queue_low;

	mode_t			 file_umask;
	gid_t			 file_group;

	size_t			 max_size;
	int			 timeout;
	int			 del_big;
	int			 ignore_errors;
	u_int			 lock_types;

	char			*def_user;
	char			*cmd_user;

	TAILQ_HEAD(, cache)	 caches;
	TAILQ_HEAD(, account)	 accounts;
	TAILQ_HEAD(, action)	 actions;
	struct rules		 rules;
};
extern struct conf		 conf;

/* Command flags. */
#define CMD_IN	0x1
#define CMD_OUT 0x2
#define CMD_ONCE 0x4

/* Command data. */
struct cmd {
	pid_t		 pid;
	int		 status;
	int		 flags;

	const char	*buf;
	size_t		 len;

	struct io	*io_in;
	struct io	*io_out;
	struct io	*io_err;
};

/* Comparison operators. */
enum cmp {
	CMP_EQ,
	CMP_NE,
	CMP_LT,
	CMP_GT
};

/* Configuration file (used by parser). */
struct file {
	FILE		*f;
	int		 line;
	const char	*path;
};
ARRAY_DECL(files, struct file *);

#ifndef HAVE_SETRESUID
#define setresuid(r, e, s) setreuid(r, e)
#endif

#ifndef HAVE_SETRESGID
#define setresgid(r, e, s) setregid(r, e)
#endif

#ifndef HAVE_STRTONUM
/* strtonum.c */
long long	 strtonum(const char *, long long, long long, const char **);
#endif

#ifndef HAVE_STRLCPY
/* strlcpy.c */
size_t		 strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCAT
/* strlcat.c */
size_t		 strlcat(char *, const char *, size_t);
#endif

/* shm.c */
char		*shm_path(struct shm *);
void		*shm_create(struct shm *, size_t);
int		 shm_owner(struct shm *, uid_t, gid_t);
void		 shm_destroy(struct shm *);
void		 shm_close(struct shm *);
void		*shm_reopen(struct shm *);
void		*shm_resize(struct shm *, size_t, size_t);

/* lex.c */
int			yylex(void);

/* parse.y */
extern struct macros	parse_macros;
extern struct files	parse_filestack;
extern struct file     *parse_file;
extern struct strb     *parse_tags;
int			parse_conf(const char *, struct strings *);
__dead printflike1 void yyerror(const char *, ...);

/* parse-fn.c */
char		*expand_path(const char *, const char *);
char		*run_command(const char *, const char *);
char		*fmt_replstrs(const char *, struct replstrs *);
char		*fmt_strings(const char *, struct strings *);
int		 have_accounts(char *);
struct account	*find_account(char *);
struct action	*find_action(char *);
struct actions	*match_actions(const char *);
struct macro	*extract_macro(char *);
struct macro	*find_macro(const char *);
void		 find_netrc(const char *, char **, char **);
int		 find_netrc1(const char *, char **, char **, char **);
void		 free_account(struct account *);
void		 free_action(struct action *);
void		 free_actitem(struct actitem *);
void		 free_cache(struct cache *);
void		 free_replstrs(struct replstrs *);
void		 free_rule(struct rule *);
void		 free_strings(struct strings *);
void		 make_actlist(struct actlist *, char *, size_t);
void		 print_action(struct action *);
void		 print_rule(struct rule *);

/* netrc.c */
FILE		*netrc_open(const char *, char **);
void		 netrc_close(FILE *);
int		 netrc_lookup(FILE *, const char *, char **, char **);

/* fdm.c */
extern volatile sig_atomic_t sigusr1;
extern volatile sig_atomic_t sigint;
extern volatile sig_atomic_t sigterm;
double		 get_time(void);
void		 dropto(uid_t, gid_t);
int		 check_incl(const char *);
int		 check_excl(const char *);
int		 use_account(struct account *, char **);
void		 fill_host(void);
__dead void	 usage(void);

/* cache-op.c */
__dead void	 cache_op(int, char **);

/* re.c */
int		 re_compile(struct re *, const char *, int, char **);
int		 re_string(struct re *, const char *, struct rmlist *, char **);
int		 re_block(struct re *, const void *, size_t, struct rmlist *,
		     char **);
void		 re_free(struct re *);

/* attach.c */
struct attach	*attach_visit(struct attach *, u_int *);
void printflike2 attach_log(struct attach *, const char *, ...);
struct attach	*attach_build(struct mail *);
void		 attach_free(struct attach *);

/* lookup.c */
struct userdata *user_lookup(const char *, struct userfunctions *);
void		 user_free(struct userdata *);
struct userdata *user_copy(struct userdata *);

/* lookup-passwd.c */
struct userdata *passwd_lookup(const char *);


/* privsep.c */
int		 privsep_send(struct io *, struct msg *, struct msgbuf *);
int		 privsep_check(struct io *);
int		 privsep_recv(struct io *, struct msg *, struct msgbuf *);

/* command.c */
struct cmd	*cmd_start(const char *, int, const char *, size_t, char **);
int		 cmd_poll(struct cmd *, char **, char **, char **, size_t *,
		     int, char **);
void		 cmd_free(struct cmd *);

/* child.c */
int		 child_fork(void);
__dead void	 child_exit(int);
struct child	*child_start(struct children *, uid_t, gid_t,
		     int (*)(struct child *, struct io *),
		     int (*)(struct child *, struct msg *, struct msgbuf *),
		     void *, struct child *);

/* child-fetch.c */
int		 open_cache(struct account *, struct cache *);
int		 child_fetch(struct child *, struct io *);

/* child-deliver.c */
int		 child_deliver(struct child *, struct io *);
void		 child_deliver_action_hook(int, struct account *, struct msg *,
		     struct child_deliver_data *, int *);
void		 child_deliver_cmd_hook(int, struct account *, struct msg *,
		     struct child_deliver_data *, int *);

/* parent-fetch.c */
int		 parent_fetch(struct child *, struct msg *, struct msgbuf *);

/* parent-deliver.c */
int		 parent_deliver(struct child *, struct msg *, struct msgbuf *);

/* timer.c */
int		 timer_expired(void);
void		 timer_set(int);
void		 timer_cancel(void);

/* connect.c */
char		*sslerror(const char *);
char		*sslerror2(int, const char *);
SSL		*makessl(struct server *, int, int, int, char **);
void		 getaddrs(const char *, char **, char **);
struct proxy	*getproxy(const char *);
struct io	*connectproxy(struct server *, int, struct proxy *,
		     const char *, int, char **);
struct io	*connectio(struct server *, int, const char *, int, char **);

/* file.c */
int printflike3	 ppath(char *, size_t, const char *, ...);
int		 vppath(char *, size_t, const char *, va_list);
int		 openlock(const char *, int, u_int);
int		 createlock(const char *, int, uid_t, gid_t, mode_t, u_int);
void		 closelock(int, const char *, u_int);
int		 locksleep(const char *, const char *, long long *);
int		 xcreate(const char *, int, uid_t, gid_t, mode_t);
int		 xmkdir(const char *, uid_t, gid_t, mode_t);
int		 xmkpath(const char *, uid_t, gid_t, mode_t);
const char	*checkmode(struct stat *, mode_t);
const char	*checkowner(struct stat *, uid_t);
const char	*checkgroup(struct stat *, gid_t);
int		 safemove(const char *, const char *);

/* mail.c */
int		 mail_open(struct mail *, size_t);
void		 mail_send(struct mail *, struct msg *);
int		 mail_receive(struct mail *, struct msg *, int);
void		 mail_close(struct mail *);
void		 mail_destroy(struct mail *);
int		 mail_resize(struct mail *, size_t);
void		 line_init(struct mail *, char **, size_t *);
void		 line_next(struct mail *, char **, size_t *);
int printflike3	 insert_header(struct mail *, const char *, const char *, ...);
int		 remove_header(struct mail *, const char *);
char		*find_header(struct mail *, const char *, size_t *, int);
char		*match_header(struct mail *, const char *, size_t *, int);
size_t		 find_body(struct mail *);
void		 count_lines(struct mail *, u_int *, u_int *);
int		 append_line(struct mail *, const char *, size_t);
char		*find_address(char *, size_t, size_t *);
void		 trim_from(struct mail *);
char		*make_from(struct mail *, char *);
u_int		 fill_wrapped(struct mail *);
void		 set_wrapped(struct mail *, char);

/* mail-time.c */
char		*rfc822time(time_t, char *, size_t);
int		 mailtime(struct mail *, time_t *);

/* mail-state.c */
int		 mail_match(struct mail_ctx *, struct msg *, struct msgbuf *);
int		 mail_deliver(struct mail_ctx *, struct msg *, struct msgbuf *);

/* db-tdb.c */
TDB_CONTEXT	*db_open(char *);
void		 db_close(TDB_CONTEXT *);
int		 db_add(TDB_CONTEXT *, char *);
int		 db_remove(TDB_CONTEXT *, char *);
int		 db_contains(TDB_CONTEXT *, char *);
int		 db_size(TDB_CONTEXT *);
int		 db_print(TDB_CONTEXT *, void (*)(const char *, ...));
int		 db_expire(TDB_CONTEXT *, uint64_t);
int		 db_clear(TDB_CONTEXT *);

/* cleanup.c */
void		 cleanup_check(void);
void		 cleanup_flush(void);
void		 cleanup_purge(void);
void		 cleanup_register(const char *);
void		 cleanup_deregister(const char *);

/* strb.c */
void		 strb_create(struct strb **);
void		 strb_clear(struct strb **);
void		 strb_destroy(struct strb **);
void		 strb_dump(struct strb *, const char *,
		     void (*)(const char *, ...));
void printflike3 strb_add(struct strb **, const char *, const char *, ...);
void		 strb_vadd(struct strb **, const char *, const char *, va_list);
struct strbent	*strb_find(struct strb *, const char *);
struct strbent	*strb_match(struct strb *, const char *);

/* replace.c */
void printflike3 add_tag(struct strb **, const char *, const char *, ...);
const char	*find_tag(struct strb *, const char *);
const char	*match_tag(struct strb *, const char *);
void		 default_tags(struct strb **, const char *);
void		 update_tags(struct strb **, struct userdata *);
void		 reset_tags(struct strb **);
char		*replacestr(struct replstr *, struct strb *, struct mail *,
		     struct rmlist *);
char		*replacepath(struct replpath *, struct strb *, struct mail *,
		     struct rmlist *, const char *);

/* log.c */
#define LOG_FACILITY LOG_MAIL
void		 log_open_syslog(int);
void		 log_open_tty(int);
void		 log_open_file(int, const char *);
void		 log_close(void);
void		 log_vwrite(int, const char *, va_list);
void		 log_write(int, const char *, ...);
void printflike1 log_warn(const char *, ...);
void printflike1 log_warnx(const char *, ...);
void printflike1 log_info(const char *, ...);
void printflike1 log_debug(const char *, ...);
void printflike1 log_debug2(const char *, ...);
void printflike1 log_debug3(const char *, ...);
__dead void	 log_vfatal(const char *, va_list);
__dead void	 log_fatal(const char *, ...);
__dead void	 log_fatalx(const char *, ...);

/* xmalloc.c */
void		*ensure_size(void *, size_t *, size_t, size_t);
void		*ensure_for(void *, size_t *, size_t, size_t);
char		*xstrdup(const char *);
void		*xcalloc(size_t, size_t);
void		*xmalloc(size_t);
void		*xrealloc(void *, size_t, size_t);
void		 xfree(void *);
int printflike2	 xasprintf(char **, const char *, ...);
int		 xvasprintf(char **, const char *, va_list);
int printflike3	 xsnprintf(char *, size_t, const char *, ...);
int		 xvsnprintf(char *, size_t, const char *, va_list);
int printflike3	 printpath(char *, size_t, const char *, ...);
char		*xdirname(const char *);
char		*xbasename(const char *);

#endif /* FDM_H */
