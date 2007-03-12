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

#ifndef MATCH_H
#define MATCH_H

/* Match return codes. */
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

/* Match attachment data. */
struct match_attachment_data {
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
		struct replstr	 str;
		struct re	 re;
	} value;
};

/* Match age data. */
struct match_age_data {
	long long	 time;
	enum cmp	 cmp;
};

/* Match size data. */
struct match_size_data {
	size_t		 size;
	enum cmp	 cmp;
};

/* Match tagged data. */
struct match_tagged_data {
	struct replstr	 tag;
};

/* Match string data. */
struct match_string_data {
	struct re	 re;

	struct replstr	 str;
};

/* Match regexp data. */
struct match_regexp_data {
	struct re	 re;

	enum area 	 area;
};

/* Match command data. */
struct match_command_data {
	struct replpath	 cmd;
	uid_t		 uid;
	int		 pipe;		/* pipe mail to command */

	struct re	 re;		/* re->re NULL to not check */
	int		 ret;		/* -1 to not check */
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

#endif
