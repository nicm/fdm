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
#include <poll.h>
#include <regex.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CONFFILE	".fdm"
#define MAXMAILSIZE	SSIZE_MAX	

extern char	*__progname;

/* Definition to shut gcc up about unused arguments in a few cases. */
#define unused __attribute__ ((unused))

/* Ensure buffer size */
#define ENSURE_SIZE(buf, len, req) do {					\
	while (len <= (req)) {						\
		buf = xrealloc(buf, 2, len);				\
		len *= 2;						\
	}								\
} while (0)

/* A single mail */
struct mail {
	char	*data;
	size_t	 size;		/* size of mail */
	size_t	 space;		/* size of malloc'd area */

	ssize_t	 body;		/* offset of body */
};

/* Account entry */
struct account {
	char			*name;

	struct fetch		*fetch;
	void			*data;

	TAILQ_ENTRY(account)	 entry;
};

/* Delivery action */
struct action {
	char			*name;

	struct deliver		*deliver;
	void			*data;

	TAILQ_ENTRY(action)	 entry;
};

/* Account name list */
struct accounts {
	char	**list;
	u_int	  num;
};
#define ACCOUNTS_INIT(a) do {						\
	(a)->num = 0;							\
	(a)->list = NULL;						\
} while (0)
#define ACCOUNTS_ADD(a, s) do {						\
	(a)->list = xrealloc((a)->list, (a)->num + 1, sizeof (char *));	\
	(a)->list[(a)->num] = s;					\
	(a)->num++;							\
} while (0)
#define ACCOUNTS_EMPTY(a) ((a) == NULL || (a)->num == 0)

/* Match areas */
enum area {
	AREA_NONE,	/* don't try to match the regexp at all */
	AREA_BODY,
	AREA_HEADERS,
	AREA_ANY
};

/* Rule entry */
struct rule {
	regex_t			 re;
	enum area		 area;

	int			 stop;	/* stop matching at this rule */

 	struct action		*action;
	struct accounts		*accounts;

	TAILQ_ENTRY(rule)	 entry;
};

/* Fetch functions */
struct fetch {
	char	*name;
	char	*port;

	int	 (*connect)(struct account *);
	int 	 (*poll)(struct account *, u_int *);
	int 	 (*fetch)(struct account *, struct mail *);
	int	 (*disconnect)(struct account *);	
};

/* Deliver functions */
struct deliver {
	char	*name;

	int	(*deliver)(struct account *, struct action *, struct mail *);
};

/* Lock types */
#define LOCK_FCNTL 0x1
#define LOCK_FLOCK 0x2
#define LOCK_DOTLOCK 0x4

/* Configuration settings */
struct conf {
	int 			 debug;
	int			 syslog;

	char			*home;
	char			*user;

	char			*conf_file;

	size_t			 max_size;
	int		         del_oversized;
	int			 check_only;
	u_int			 lock_types;

	TAILQ_HEAD(, account)	 accounts;
 	TAILQ_HEAD(, action)	 actions;
 	TAILQ_HEAD(, rule)	 rules;
};
extern struct conf		 conf;

/* Shorthand for the ridiculous call to get the SSL error */
#define ssl_err() (ERR_error_string(ERR_get_error(), NULL))

/* Limits at which to abort. Would die when memory ran out anyway but better
   to die at a ridiculous point rather than an insane one */
#define IO_MAXLINELEN 1048576
#define IO_MAXBUFFERLEN 8388608

/* IO line endings */
#define IO_CRLF "\r\n"
#define IO_CR   "\r"
#define IO_LF   "\n"

/* Amount to attempt to append to the buffer each time */
#define IO_BLKSIZE 1024

/* IO structure */
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

/* stdin data */
struct stdin_data {
	struct io		*io;
};

/* pop3 states */
enum pop3_state {
	POP3_CONNECTING,
	POP3_USER,
	POP3_PASS,
	POP3_STAT,
	POP3_LIST,
	POP3_RETR,
	POP3_LINE,
	POP3_DELE,
	POP3_DONE,
	POP3_QUIT
};

/* pop3 data */
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

/* pop3 macros */
#define pop3_isOK(s) (strncmp(s, "+OK", 3) == 0)
#define pop3_isERR(s) (strncmp(s, "+ERR", 4) == 0)

/* fetch-stdin.c */
extern struct fetch 	 fetch_stdin;

/* fetch-pop3.c */
extern struct fetch 	 fetch_pop3;
int			 pop3_poll(struct account *, u_int *);
int			 pop3_fetch(struct account *, struct mail *);

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

/* connect.c */
int			 connectto(struct addrinfo *, char **);

/* mail.c */
int			 openlock(char *, u_int, int, mode_t);
void			 closelock(int, char *, u_int);
int			 has_from(struct mail *);
void			 trim_from(struct mail *);

/* replace.c */
#define REPL_LEN 52
#define REPL_IDX(ch) ((ch >= 'a' || ch <= 'z') ? ch - 'a' : 		\
	((ch >= 'A' || ch <= 'z') ? 26 + ch - 'A' : -1))
char 			*replace(char *, char *[52]);

/* io.c */
struct io		*io_create(int, SSL *, const char [2]);
void			 io_free(struct io *);
int			 io_poll(struct io *io);
void 			*io_read(struct io *, size_t);
void			 io_write(struct io *, const void *, size_t);
char 			*io_readline(struct io *);
void			 io_writeline(struct io *, const char *, ...);
void			 io_vwriteline(struct io *, const char *, va_list);
int			 io_flush(struct io *);
int			 io_wait(struct io *, size_t);

/* log.c */
void			 log_init(int);
void		    	 vlog(int, const char *, va_list);
void			 log_warn(const char *, ...);
void			 log_warnx(const char *, ...);
void			 log_info(const char *, ...);
void			 log_debug(const char *, ...);
void			 log_debug2(const char *, ...);
__dead void		 fatal(const char *);
__dead void		 fatalx(const char *);

/* xmalloc.c */
char			*xstrdup(const char *);
void			*xcalloc(size_t, size_t);
void			*xmalloc(size_t);
void			*xrealloc(void *, size_t, size_t);
void			 xfree(void *);
int			 xasprintf(char **, const char *, ...);
int			 xsnprintf(char *, size_t, const char *, ...);

#endif
