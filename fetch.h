/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
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

#ifndef FETCH_H
#define FETCH_H

/* Fetch return codes. */
#define FETCH_ERROR 0
#define FETCH_COMPLETE 1
#define FETCH_AGAIN 2		/* may poll but must not block */
#define FETCH_BLOCK 3		/* may block if necessary */
#define FETCH_HOLD 4		/* don't need to poll at all */

/* Fetch context. */
struct fetch_ctx {
	struct mail_queue 	 matchq;
	struct mail_queue 	 deliverq;
	struct mail_queue	 doneq;

	u_int		  	 dropped;
	u_int		  	 kept;

	u_int			 queued;  /* number of mails queued */
	int			 blocked; /* blocked for parent */
	int	 		 holding; /* holding fetch until queues drop */

	struct io	        *io;
};

/* Fetch functions. */
struct fetch {
	const char	*name;

 	int		 (*connect)(struct account *);
	void		 (*fill)(struct account *, struct io **, u_int *n);
 	u_int		 (*total)(struct account *);
	int		 (*completed)(struct account *); 
	int		 (*closed)(struct account *);
	int	 	 (*fetch)(struct account *, struct fetch_ctx *fctx);
	int	 	 (*poll)(struct account *);
	int		 (*purge)(struct account *);
	int		 (*close)(struct account *);
	int		 (*disconnect)(struct account *);
	void		 (*desc)(struct account *, char *, size_t);
};

/* Fetch maildir data. */
struct fetch_maildir_data {
	struct strings	*maildirs;

	struct strings	*paths;
	u_int		 index;

	int 	         (*state)(struct account *, struct fetch_ctx *); 

	DIR		*dirp;
	char		*path;
};

struct fetch_maildir_mail {
	char		 path[MAXPATHLEN];
};

/* NNTP group entry. */
struct fetch_nntp_group {
	char		*name;
	int		 ignore;

	u_int		 size;
	u_int		 last;
	char		*id;
};

/* Fetch nntp data. */
struct fetch_nntp_data {
	char		*path;

	struct server	 server;
	struct strings	*names;

	u_int		 group;
	ARRAY_DECL(, struct fetch_nntp_group *) groups;

	int 	         (*state)(struct account *, struct fetch_ctx *); 
	int		 close;

	struct mail	*mail;
	int		 flushing;
	int		 bodylines;
	u_int		 lines;
	size_t		 size;

	size_t		 llen;
	char		*lbuf;

	struct io	*io;
};

/* Fetch stdin data. */
struct fetch_stdin_data {
	int		 complete;

	int		 bodylines;
	u_int		 lines;

	size_t		 llen;
	char		*lbuf;

	struct io	*io;
};

/* Fetch pop3 data. */
struct fetch_pop3_data {
	char		*user;
	char		*pass;
	struct server	 server;

	u_int		 cur;
	u_int		 num;
	u_int		 total;	

	int 	         (*state)(struct account *, struct fetch_ctx *); 
	struct strings	 kept;
	int		 purge;
	int		 close;

	struct mail	*mail;
	int		 flushing;
	int		 bodylines;
	u_int		 lines;
	size_t		 size;

	size_t		 llen;
	char		*lbuf;

	struct io	*io;
};

struct fetch_pop3_mail {
	char		*uid;
	u_int		 idx;
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
struct fetch_imap_data {
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

	enum {
		IMAP_START,
		IMAP_UID1,
		IMAP_UID2,
		IMAP_FETCH,
		IMAP_LINE,
		IMAP_END1,
		IMAP_END2
	} state;
	int		 flushing;
	int		 bodylines;
	u_int		 lines;
	size_t		 size;

	char		*src;

	size_t		 llen;
	char		*lbuf;

	int		 (*pollln)(struct account *a, char **);
	int		 (*getln)(struct account *a, char **);
	int		 (*putln)(struct account *a, const char *, va_list);
	void		 (*flush)(struct account *a);
};

struct fetch_imap_mail {
	u_int		 uid;
	u_int		 idx;
};

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

/* imap-common.c */
int			 imap_start(struct account *);
int			 imap_finish(struct account *);
int			 imap_login(struct account *);
int			 imap_select(struct account *);
int			 imap_close(struct account *);
int			 imap_logout(struct account *);
void			 imap_abort(struct account *);
int			 imap_uid(struct account *);
int			 imap_poll(struct account *, u_int *);
int			 imap_fetch(struct account *, struct mail *);
int			 imap_purge(struct account *);
int			 imap_done(struct account *, struct mail *);

/* mail-callback.c */
void			 transform_mail(struct account *, struct fetch_ctx *,
    			     struct mail *);
int			 enqueue_mail(struct account *, struct fetch_ctx *,
			     struct mail *);
int			 empty_mail(struct account *, struct fetch_ctx *,
			     struct mail *);
int			 oversize_mail(struct account *, struct fetch_ctx *,
			     struct mail *);
struct mail 		*done_mail(struct account *, struct fetch_ctx *);
void			 dequeue_mail(struct account *, struct fetch_ctx *);
int		  	 can_purge(struct account *, struct fetch_ctx *);

#endif
