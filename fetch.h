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
#define FETCH_AGAIN 1
#define FETCH_BLOCK 2
#define FETCH_ERROR 3
#define FETCH_MAIL 4
#define FETCH_EXIT 5

/* Fetch flags. */
#define FETCH_PURGE 0x1
#define FETCH_EMPTY 0x2
#define FETCH_POLL 0x4

/* Fetch context. */
struct fetch_ctx {
	int		 (*state)(struct account *, struct fetch_ctx *);
	int		 flags;

	struct mail	*mail;

	size_t		 llen;
	char		*lbuf;
};

/* Fetch functions. */
struct fetch {
	const char	*name;
	int		 (*first)(struct account *, struct fetch_ctx *);

	void		 (*fill)(struct account *, struct iolist *);
	int		 (*commit)(struct account *, struct mail *);
	void		 (*abort)(struct account *);
	u_int		 (*total)(struct account *);
	void		 (*desc)(struct account *, char *, size_t);
};

/* Ranges of mail. */
enum fetch_only {
	FETCH_ONLY_NEW,
	FETCH_ONLY_OLD,
	FETCH_ONLY_ALL
};

/* Fetch maildir data. */
struct fetch_maildir_data {
	struct strings	*maildirs;

	u_int		 total;

	struct strings	 unlinklist;

	struct strings	*paths;
	u_int		 index;
	DIR		*dirp;
};

struct fetch_maildir_mail {
	char		 path[MAXPATHLEN];
};

/* Fetch mbox data. */
struct fetch_mbox_data {
	struct strings	*mboxes;

	ARRAY_DECL(, struct fetch_mbox_mbox *) fmboxes;
	u_int		 index;

	size_t		 off;

	TAILQ_HEAD(, fetch_mbox_mail) kept;
};

struct fetch_mbox_mbox {
	char		*path;
	u_int		 reference;
	u_int		 total;

	int		 fd;
	char		*base;
	size_t		 size;
};

struct fetch_mbox_mail {
	size_t		 off;
	size_t		 size;

	struct fetch_mbox_mbox *fmbox;

	TAILQ_ENTRY(fetch_mbox_mail) entry;
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

	char		*user;
	char		*pass;
	struct server	 server;
	struct strings	*names;

	u_int		 group;
	ARRAY_DECL(, struct fetch_nntp_group *) groups;

	int		 flushing;

	struct io	*io;
};

/* Fetch pop3 queues and trees. */
TAILQ_HEAD(fetch_pop3_queue, fetch_pop3_mail);
RB_HEAD(fetch_pop3_tree, fetch_pop3_mail);

/* Fetch pop3 data. */
struct fetch_pop3_data {
	char		*path;
	enum fetch_only	 only;

	char		*user;
	char		*pass;
	struct server	 server;
	char		*pipecmd;
	int		 starttls;
	int		 apop;
	int		 uidl;

	u_int		 cur;
	u_int		 num;

	u_int		 total;
	u_int		 committed;

	/* Mails on the server. */
	struct fetch_pop3_tree	serverq;

	/* Mails in the cache file. */
	struct fetch_pop3_tree	cacheq;

	/* Mails to fetch from the server. */
	struct fetch_pop3_queue	wantq;

	/* Mails ready to be dropped. */
	struct fetch_pop3_queue dropq;

	int		 flushing;
	size_t		 size;

	struct io	*io;
	struct cmd	*cmd;

	char		*src;
	int		 (*connect)(struct account *);
	void		 (*disconnect)(struct account *);
	int		 (*getln)(
			      struct account *, struct fetch_ctx *, char **);
	int		 (*putln)(struct account *, const char *, va_list);
};

struct fetch_pop3_mail {
	char		*uid;
	u_int		 idx;

	TAILQ_ENTRY(fetch_pop3_mail) qentry;
	RB_ENTRY(fetch_pop3_mail) tentry;
};

/* Fetch imap data. */
struct fetch_imap_data {
	enum fetch_only	 only;

	char		*user;
	char		*pass;
	struct server	 server;
	char		*pipecmd;
	int		 starttls;
	int		 nocrammd5;
	int		 nologin;

	u_int		 folder;
	struct strings	*folders;
	u_int		 folders_total; /* total mail count */

	int		 capa;
	int		 tag;

	ARRAY_DECL(, u_int) wanted;
	ARRAY_DECL(, u_int) dropped;
	ARRAY_DECL(, u_int) kept;

	u_int		 total;
	u_int		 committed;

	int		 flushing;
	size_t		 size;
	u_int		 lines;

	struct io	*io;
	struct cmd	*cmd;

	char		*src;
	int		 (*connect)(struct account *);
	void		 (*disconnect)(struct account *);
	int		 (*getln)(
			      struct account *, struct fetch_ctx *, char **);
	int		 (*putln)(struct account *, const char *, va_list);
};

struct fetch_imap_mail {
	u_int		 uid;
};

#define IMAP_TAG_NONE -1
#define IMAP_TAG_CONTINUE -2
#define IMAP_TAG_ERROR -3

#define IMAP_TAGGED 0
#define IMAP_CONTINUE 1
#define IMAP_UNTAGGED 2
#define IMAP_RAW 3

#define IMAP_CAPA_AUTH_CRAM_MD5 0x1
#define IMAP_CAPA_XYZZY 0x2
#define IMAP_CAPA_STARTTLS 0x4

/* fetch-maildir.c */
extern struct fetch	 fetch_maildir;

/* fetch-mbx.c */
extern struct fetch	 fetch_mbox;

/* fetch-stdin.c */
extern struct fetch	 fetch_stdin;

/* fetch-nntp.c */
extern struct fetch	 fetch_nntp;

/* fetch-pop3.c */
extern struct fetch	 fetch_pop3;

/* fetch-pop3pipe.c */
extern struct fetch	 fetch_pop3pipe;

/* fetch-imap.c */
extern struct fetch	 fetch_imap;
int	fetch_imap_putln(struct account *, const char *, va_list);
int	fetch_imap_getln(struct account *, struct fetch_ctx *, char **);
int	fetch_imap_state_init(struct account *, struct fetch_ctx *);

/* fetch-imappipe.c */
extern struct fetch	 fetch_imappipe;

/* imap-common.c */
int	imap_tag(char *);
int	imap_putln(struct account *, const char *, ...);
int	imap_getln(struct account *, struct fetch_ctx *, int, char **);
int	imap_okay(char *);
int	imap_no(char *);
int	imap_bad(struct account *, const char *);
int	imap_invalid(struct account *, const char *);
int	imap_state_init(struct account *, struct fetch_ctx *);
int	imap_state_connected(struct account *, struct fetch_ctx *);
int	imap_state_select1(struct account *, struct fetch_ctx *);
int	imap_commit(struct account *, struct mail *);
void	imap_abort(struct account *);
u_int	imap_total(struct account *);

/* pop3-common.c */
int	pop3_state_init(struct account *, struct fetch_ctx *);
int	pop3_commit(struct account *, struct mail *);
void	pop3_abort(struct account *);
u_int	pop3_total(struct account *);

#endif
