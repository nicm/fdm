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
#define FETCH_SUCCESS 0
#define FETCH_ERROR 1
#define FETCH_OVERSIZE 2
#define FETCH_COMPLETE 3

/* Fetch functions. */
struct fetch {
#define FETCHPORT_NORMAL 0
#define FETCHPORT_SSL 1
	const char	*ports[2];	/* normal port, ssl port */

	int		 (*init)(struct account *);
	int	 	 (*connect)(struct account *);
	int 		 (*poll)(struct account *, u_int *);
	int	 	 (*fetch)(struct account *, struct mail *);
	int		 (*purge)(struct account *);
	int		 (*done)(struct account *, enum decision);
	int		 (*disconnect)(struct account *);
	int		 (*free)(struct account *);
	void		 (*desc)(struct account *, char *, size_t);
};

/* Fetch maildir data. */
struct fetch_maildir_data {
	struct strings	*maildirs;

	struct strings	*paths;
	u_int		 index;

	DIR		*dirp;
	char		*path;
	char		 entry[MAXPATHLEN];
	char		 maildir[MAXPATHLEN];
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

	u_int			 group;
	ARRAY_DECL(, struct fetch_nntp_group *) groups;

	struct io	*io;
};

/* Fetch stdin data. */
struct fetch_stdin_data {
	int		 complete;

	struct io	*io;
};

/* Fetch pop3 data. */
struct fetch_pop3_data {
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

	char		*src;

	size_t		 llen;
	char		*lbuf;

	char		*(*getln)(struct account *a, int);
	int		 (*putln)(struct account *a, const char *, ...);
	void		 (*flush)(struct account *a);
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
int			 imap_done(struct account *, enum decision);

#endif
