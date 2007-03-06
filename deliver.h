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

#ifndef DELIVER_H
#define DELIVER_H

/* Deliver return codes. */
#define DELIVER_SUCCESS 0
#define DELIVER_FAILURE 1

/* Deliver context. */
struct deliver_ctx {
	struct account	*account;
	struct mail	*mail;

	struct mail	 wr_mail;

	enum decision	*decision;

	int		*pm_valid;
	regmatch_t	 pm[NPMATCH];
};

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

/* Deliver smtp states. */
enum deliver_smtp_state {
	SMTP_CONNECTING,
	SMTP_HELO,
	SMTP_FROM,
	SMTP_TO,
	SMTP_DATA,
	SMTP_DONE,
	SMTP_QUIT
};

/* Deliver smtp data. */
struct deliver_smtp_data {
	struct server	 server;
	char		*to;
};

/* Deliver mbox data. */
struct deliver_mbox_data {
	char		*path;
	int		 compress;
};

/* Deliver stdout data. */
struct deliver_stdout_data {
	int		 add_from;
};

/* Deliver add-header data. */
struct deliver_add_header_data {
	char		*hdr;
	char		*value;
};

/* deliver-smtp.c */
extern struct deliver	 deliver_smtp;

/* deliver-smtp.c */
extern struct deliver	 deliver_stdout;

/* deliver-pipe.c */
extern struct deliver 	 deliver_pipe;
int	 		 do_pipe(struct deliver_ctx *, struct action *, int);

/* deliver-exec.c */
extern struct deliver 	 deliver_exec;

/* deliver-drop.c */
extern struct deliver 	 deliver_drop;

/* deliver-keep.c */
extern struct deliver 	 deliver_keep;

/* deliver-maildir.c */
extern struct deliver 	 deliver_maildir;

/* deliver-remove-header.c */
extern struct deliver	 deliver_remove_header;

/* deliver-add-header.c */
extern struct deliver	 deliver_add_header;

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

#endif
