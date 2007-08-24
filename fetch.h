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
	int 	         (*state)(struct account *, struct fetch_ctx *);
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

/* Fetch maildir data. */
struct fetch_maildir_data {
	struct strings	*maildirs;

	u_int		 total;

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
	char	        *path;
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

	struct server	 server;
	struct strings	*names;

	u_int		 group;
	ARRAY_DECL(, struct fetch_nntp_group *) groups;

	int		 flushing;

	struct io	*io;
};

/* Fetch pop3 data. */
struct fetch_pop3_data {
	char		*user;
	char		*pass;
	struct server	 server;
	int		 apop;

	u_int		 cur;
	u_int		 num;

	u_int		 total;
	u_int		 committed;

	struct strings	 kept;
	TAILQ_HEAD(, fetch_pop3_mail) dropped;

	int		 flushing;
	size_t		 size;

	struct io	*io;
};

struct fetch_pop3_mail {
	char		*uid;
	u_int		 idx;

	TAILQ_ENTRY(fetch_pop3_mail) entry;
};

/* Fetch imap data. */
struct fetch_imap_data {
	char		*user;
	char		*pass;
	char		*folder;
	struct server	 server;
	char		*pipecmd;

	int		 capa;
	int		 tag;

	u_int		 cur;
	u_int		 num;

	u_int		 total;
	u_int		 committed;

	u_int	 	 uid;

	ARRAY_DECL(, u_int) kept;
	TAILQ_HEAD(, fetch_imap_mail) dropped;

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
	u_int		 idx;

	TAILQ_ENTRY(fetch_imap_mail) entry;
};

/* fetch-maildir.c */
extern struct fetch 	 fetch_maildir;

/* fetch-mbx.c */
extern struct fetch 	 fetch_mbox;

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
int	imap_state_connect(struct account *, struct fetch_ctx *);
int	imap_commit(struct account *, struct mail *);
void	imap_abort(struct account *);
u_int	imap_total(struct account *);

#endif
