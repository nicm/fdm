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

#include <sys/types.h>
#include <sys/queue.h>

#include <stdarg.h>
#include <regex.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHILDUSER	"_fdm"
#define CONFFILE	".fdm.conf"
#define MAXMAILSIZE	INT_MAX
#define DEFMAILSIZE	(1 * 1024 * 1024 * 1024)	/* 1 GB */
#define LOCKSLEEPTIME	2
#define MAXNAMESIZE	32

extern char	*__progname;

#ifndef __dead
#define __dead
#endif

#ifndef TAILQ_FIRST
#define TAILQ_FIRST(head) (head)->tqh_first
#endif
#ifndef TAILQ_END
#define TAILQ_END(head) NULL
#endif
#ifndef TAILQ_NEXT
#define TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#endif
#ifndef TAILQ_FOREACH
#define TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST(head);					\
	     (var) != TAILQ_END(head);				 	\
	     (var) = TAILQ_NEXT(var, field))
#endif
#ifndef TAILQ_EMPTY
#define TAILQ_EMPTY(head) (TAILQ_FIRST(head) == TAILQ_END(head))
#endif

#define ARRAY_INIT(a) do {						\
	(a)->num = 0;							\
	(a)->list = NULL;      						\
} while (0)
#define ARRAY_ADD(a, s, c) do {						\
	(a)->list = xrealloc((a)->list, (a)->num + 1, sizeof (c));	\
	((c *) (a)->list)[(a)->num] = s;				\
	(a)->num++;							\
} while (0)
#define ARRAY_EMPTY(a) ((a) == NULL || (a)->num == 0)
#define ARRAY_LENGTH(a) ((a)->num)
#define ARRAY_ITEM(a, n, c) (((c *) (a)->list)[n])

/* Definition to shut gcc up about unused arguments in a few cases. */
#define unused __attribute__ ((unused))

/* Attribute to make gcc check printf-like arguments. */
#define printflike1 __attribute__ ((format (printf, 1, 2)))
#define printflike2 __attribute__ ((format (printf, 2, 3)))
#define printflike3 __attribute__ ((format (printf, 3, 4)))

/* Ensure buffer size. */
#define ENSURE_SIZE(buf, len, req) do {					\
	while ((len) <= (req)) {					\
		(buf) = xrealloc((buf), 2, (len));			\
		(len) *= 2;						\
	}								\
} while (0)

/* Valid email address chars. */
#define isaddr(c) ( 							\
	((c) >= 'a' && (c) <= 'z') || 					\
	((c) >= 'A' && (c) <= 'Z') ||					\
	((c) >= '0' && (c) <= '9') ||					\
	(c) == '&' || (c) == '*' || (c) == '+' || (c) == '?' ||	 	\
	(c) == '-' || (c) == '.' || (c) == '=' || (c) == '/' ||		\
	(c) == '^' || (c) == '{' || (c) == '}' || (c) == '~' || 	\
	(c) == '_' || (c) == '@' || (c) == '\'')

/* Command-line commands. */
enum cmd {
	CMD_NONE,
	CMD_POLL,
	CMD_FETCH
};

/* A single mail. */
struct mail {
	char	*base;
	
	char	*data;
	size_t	 size;		/* size of mail */
	size_t	 space;		/* size of malloc'd area */

	char	*from;		/* from line */

	size_t	*wrapped;	/* list of wrapped lines */

	ssize_t	 body;		/* offset of body */
};

/* Privsep message types. */
enum type {
	MSG_DELIVER,
	MSG_EXIT,
	MSG_DONE
};

/* Privsep message. */
struct msg {
	enum type	 type;
	int	 	 error;

	struct mail	 mail;

	/* these only work so long as they aren't moved in either process */
	struct rule	*rule;
	struct account	*acct;
};

/* Account entry. */
struct account {
	char			 name[MAXNAMESIZE];

	struct fetch		*fetch;
	void			*data;

	TAILQ_ENTRY(account)	 entry;
};

/* Action definition. */
struct action {
	char			 name[MAXNAMESIZE];

	struct users		*users;
	int			 find_uid;

	struct deliver		*deliver;
	void			*data;

	TAILQ_ENTRY(action)	 entry;
};

/* Accounts array. */
struct accounts {
	char	**list;
	u_int	  num;
};

/* Actions array. */
struct actions {
	struct action	**list;
	u_int	  	  num;
};

/* Match areas. */
enum area {
	AREA_BODY,
	AREA_HEADERS,
	AREA_ANY
};

/* Match operators. */
enum op {
	OP_NONE,
	OP_AND,
	OP_OR
};

/* Match regexps. */
struct match {
	char			*s;	

	regex_t			 re;
	enum op			 op;
	enum area	 	 area;

	TAILQ_ENTRY(match)	 entry;
};

/* Match struct. */
TAILQ_HEAD(matches, match);

/* Rule types. */
enum ruletype {
	RULE_MATCHES,
	RULE_ALL,
	RULE_MATCHED,
	RULE_UNMATCHED
};

/* Rule entry. */
struct rule {
	u_int			 index;

	struct matches		*matches;
	enum ruletype		 type;

	struct users		*users;
	int			 find_uid;	/* find uids from headers */

	int			 stop;		/* stop matching at this rule */

	struct actions		*actions;
	struct accounts		*accounts;

	TAILQ_ENTRY(rule)	 entry;
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
	char	*name;
	char	*port;

	int	 (*connect)(struct account *);
	int 	 (*poll)(struct account *, u_int *);
	int 	 (*fetch)(struct account *, struct mail *);
	int	 (*delete)(struct account *);
	void	 (*error)(struct account *);
	int	 (*disconnect)(struct account *);	
};

/* Deliver functions. */
struct deliver {
	char	*name;

	int	(*deliver)(struct account *, struct action *, struct mail *);
};

/* Lock types. */
#define LOCK_FCNTL 0x1
#define LOCK_FLOCK 0x2
#define LOCK_DOTLOCK 0x4

/* Domains array. */
struct domains {
	char	**list;
	u_int	  num;
};

/* Headers array. */
struct headers {
	char	**list;
	u_int	  num;
};

/* Users array. */
struct users {
	char	**list;
	u_int	  num;
};

/* Configuration settings. */
struct conf {
	int 			 debug;
	int			 syslog;

	uid_t			 child_uid;
	char			*child_path;

	struct accounts	 	 incl;
	struct accounts		 excl;

	struct domains		*domains; /* domains to look for with users */
	struct headers		*headers; /* headers to search for users */

	struct {
		char		*home;
		char		*user;
		char		*uid;
		char		*host;
	} info;

	char			*conf_file;
	int			 check_only;

	size_t			 max_size;
	int		         del_big;
	u_int			 lock_types;
	uid_t			 def_user;

	TAILQ_HEAD(, account)	 accounts;
 	TAILQ_HEAD(, action)	 actions;
 	TAILQ_HEAD(, rule)	 rules;
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

/* Amount to poll after in io_accept. */
#define IO_FLUSHSIZE (8 * IO_BLOCKSIZE)

/* IO structure. */
struct io {
	int		 fd;
	int		 dup_fd;	/* dup all data to this fd */
	SSL		*ssl;

	int		 closed;
	int		 need_wr;

	char		*rbase;		/* buffer start */
	size_t		 rspace;	/* total size of buffer */
	size_t		 rsize;		/* amount of data available */
	size_t		 roff;		/* base of data in buffer */

	char		*wbase;		/* buffer start */
	size_t		 wspace;	/* total size of buffer */
	size_t		 wsize;		/* size of data currently in buffer */

	const	 char	*eol;
};

/* Fetch stdin data. */
struct stdin_data {
	struct io		*io;

	int			 complete;
};

/* Fetch pop3 states. */
enum pop3_state {
	POP3_CONNECTING,
	POP3_USER,
	POP3_PASS,
	POP3_STAT,
	POP3_LIST,
	POP3_RETR,
	POP3_LINE,
	POP3_DONE,
	POP3_QUIT
};

/* Fetch pop3 data. */
struct pop3_data {
	char			*user;
	char			*pass;

	struct addrinfo		*ai;
	int			 fd;

	enum pop3_state	 	 state;
	u_int		 	 cur;
	u_int		 	 num;

        SSL_CTX			*ctx;
	struct io		*io;
};

/* Fetch pop3 macros. */
#define pop3_isOK(s) (strncmp(s, "+OK", 3) == 0)
#define pop3_isERR(s) (strncmp(s, "+ERR", 4) == 0)

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
	struct addrinfo		*ai;
	char			*to;
};

/* fetch-stdin.c */
extern struct fetch 	 fetch_stdin;

/* fetch-pop3.c */
extern struct fetch 	 fetch_pop3;
int			 pop3_poll(struct account *, u_int *);
int			 pop3_fetch(struct account *, struct mail *);
int			 pop3_delete(struct account *);
void			 pop3_error(struct account *);

/* fetch-pop3s.c */
extern struct fetch 	 fetch_pop3s;

/* deliver-smtp.c */
extern struct deliver	 deliver_smtp;

/* deliver-pipe.c */
extern struct deliver 	 deliver_pipe;

/* deliver-drop.c */
extern struct deliver 	 deliver_drop;

/* deliver-maildir.c */
extern struct deliver 	 deliver_maildir;

/* deliver-mbox.c */
extern struct deliver 	 deliver_mbox;

/* deliver-write.c */
extern struct deliver 	 deliver_write;
int	 do_write(struct account *, struct action *, struct mail *, int);

/* deliver-append.c */
extern struct deliver 	 deliver_append;

#ifdef NO_STRLCPY
/* strlcpy.c */
size_t	 strlcpy(char *, const char *, size_t);
#endif

#ifdef NO_STRLCAT
/* strlcat.c */
size_t	 strlcat(char *, const char *, size_t);
#endif

/* fdm.c */
int			 dropto(uid_t, char *);
void			 fill_info(char *);

/* child.c */
int			 child(int, enum cmd);

/* parent.c */
int			 parent(int, pid_t);

/* connect.c */
int			 connectto(struct addrinfo *, char **);

/* mail.c */
void			 free_mail(struct mail *);
void			 resize_mail(struct mail *, size_t);
int			 openlock(char *, u_int, int, mode_t);
void			 closelock(int, char *, u_int);
void			 line_init(struct mail *, char **, size_t *);
void			 line_next(struct mail *, char **, size_t *);
char 			*find_header(struct mail *, char *, size_t *);
struct users		*find_users(struct mail *);
char			*find_address(char *, size_t, size_t *);
void			 trim_from(struct mail *);
void			 make_from(struct mail *);
u_int			 fill_wrapped(struct mail *);
void			 set_wrapped(struct mail *, char);
void			 free_wrapped(struct mail *);

/* replace.c */
#define REPL_LEN 52
#define REPL_IDX(ch) /* LINTED */ 				\
	((ch >= 'a' || ch <= 'z') ? ch - 'a' :			\
	((ch >= 'A' || ch <= 'z') ? 26 + ch - 'A' : -1))
char			*replaceinfo(char *, struct account *, struct action *);
char 			*replace(char *, char *[52]);

/* io.c */
struct io		*io_create(int, SSL *, const char [2]);
void			 io_free(struct io *);
int			 io_update(struct io *);
int			 io_poll(struct io *);
int			 io_read2(struct io *, void *, size_t);
void 			*io_read(struct io *, size_t);
void			 io_write(struct io *, const void *, size_t);
char 			*io_readline2(struct io *, char **, size_t *);
char 			*io_readline(struct io *);
void printflike2	 io_writeline(struct io *, const char *, ...);
void			 io_vwriteline(struct io *, const char *, va_list);
int			 io_flush(struct io *);
int			 io_wait(struct io *, size_t);

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
#ifdef DEBUG
void			 xmalloc_clear(void);
void			 xmalloc_dump(char *);
#endif
char			*xstrdup(const char *);
void			*xcalloc(size_t, size_t);
void			*xmalloc(size_t);
void			*xrealloc(void *, size_t, size_t);
void			 xfree(void *);
int printflike2		 xasprintf(char **, const char *, ...);
int printflike3	 	 xsnprintf(char *, size_t, const char *, ...);

#endif /* FDM_H */
