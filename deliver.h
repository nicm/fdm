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
	double		 		 tim;

	struct action			*action;
	struct actitem			*actitem;
	struct rule			*rule;

	struct account			*account;
	struct mail			*mail;

	uid_t				 uid;

	struct mail	 		 wr_mail;

	TAILQ_ENTRY(deliver_ctx)	 entry;
};

/* Delivery types. */
enum delivertype {
	DELIVER_INCHILD,/* don't pass to parent */
	DELIVER_ASUSER,	/* pass to parent to drop privs */
	DELIVER_WRBACK	/* modifies mail: pass to parent and receive new mail */
};

/* Deliver functions. */
struct deliver {
	const char	*name;
	enum delivertype type;

	int	 	 (*deliver)(struct deliver_ctx *, struct actitem *);
	void		 (*desc)(struct actitem *, char *, size_t);
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
	struct server	server;
	struct replstr	to;
};

/* Deliver mbox data. */
struct deliver_mbox_data {
	struct replpath	path;
	int		compress;
};

/* Deliver add-header data. */
struct deliver_add_header_data {
	struct replstr	hdr;
	struct replstr	value;
};

/* Deliver remove-header data. */
struct deliver_remove_header_data {
	struct replstr	hdr;
};

/* Deliver write data. */
struct deliver_write_data {
	struct replpath	path;
};

/* Deliver maildir data. */
struct deliver_maildir_data {
	struct replpath	path;
};

/* Deliver rewrite data. */
struct deliver_rewrite_data {
	struct replpath	cmd;
};

/* Deliver pipe data. */
struct deliver_pipe_data {
	struct replpath	cmd;
};

/* Deliver tag data. */
struct deliver_tag_data {
	struct replstr	 key;
	struct replstr	 value;
};

/* Deliver action data. */
struct deliver_action_data {
	struct replstrs	*actions;
};

/* Deliver rewrite data. */
struct deliver_to_cache_data {
	char		*path;
	struct replstr	 key;
};

/* deliver-smtp.c */
extern struct deliver	 deliver_smtp;

/* deliver-stdout.c */
extern struct deliver	 deliver_stdout;

/* deliver-tag.c */
extern struct deliver	 deliver_tag;

/* deliver-pipe.c */
extern struct deliver 	 deliver_pipe;
int	 		 do_pipe(struct deliver_ctx *, struct actitem *, int);

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

/* deliver-mbox.c */
extern struct deliver 	 deliver_mbox;

/* deliver-write.c */
extern struct deliver 	 deliver_write;
int	 		 do_write(struct deliver_ctx *, struct actitem *, int);

/* deliver-append.c */
extern struct deliver 	 deliver_append;

/* deliver-rewrite.c */
extern struct deliver 	 deliver_rewrite;

/* deliver-to-cache.c */
extern struct deliver 	 deliver_to_cache;

#endif
