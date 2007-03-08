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

/* Declarations */

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <ctype.h>
#include <fnmatch.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "fdm.h"
#include "deliver.h"
#include "fetch.h"
#include "match.h"

struct macros	macros = TAILQ_HEAD_INITIALIZER(macros);
u_int		ruleidx;

struct fileent {
	FILE			*yyin;
	int		 	 yylineno;
	char			*curfile;
};
ARRAY_DECL(, struct fileent *)	 filestack;
char				*curfile;

ARRAY_DECL(, struct rule *)	 rulestack;
struct rule			*currule;

extern FILE			*yyin;
extern int		 	 yylineno;
extern int 		 	 yylex(void);
extern void		 	 yyrestart(FILE *);

int			 	 yyparse(void);
__dead printflike1 void  	 yyerror(const char *, ...);
int 			 	 yywrap(void);

struct account 			*find_account(char *);
int				 have_accounts(char *);
struct action  			*find_action(char *);

__dead printflike1 void
yyerror(const char *fmt, ...)
{
	va_list	 ap;
	char	*s, *file;

	file = curfile == NULL ? conf.conf_file : curfile;
	xasprintf(&s, "%s: %s at line %d", file, fmt, yylineno);

	va_start(ap, fmt);
	vlog(LOG_CRIT, s, ap);
	va_end(ap);

	exit(1);
}

int
yywrap(void)
{
	struct macro		*macro;
	struct fileent		*top;
	char			*file;

	file = curfile == NULL ? conf.conf_file : curfile;
	log_debug2("finished file %s", file);

	if (ARRAY_EMPTY(&filestack)) {
		while (!TAILQ_EMPTY(&macros)) {
			macro = TAILQ_FIRST(&macros);
			TAILQ_REMOVE(&macros, macro, entry);
			if (macro->type == MACRO_STRING)
				xfree(macro->value.str);
			xfree(macro);
		}

		ARRAY_FREE(&filestack);
		if (!ARRAY_EMPTY(&rulestack))
			yyerror("missing }");
		ARRAY_FREE(&rulestack);
		return (1);
	}

	top = ARRAY_LAST(&filestack, struct fileent *);
	yyin = top->yyin;
	yyrestart(yyin);
	yylineno = top->yylineno;
	xfree(curfile);
	curfile = top->curfile;
	xfree(top);
	ARRAY_TRUNC(&filestack, 1, struct fileent *);

        return (0);
}

struct strings *
weed_strings(struct strings *sp)
{
	u_int	 i, j;
	char	*s;

	if (ARRAY_LENGTH(sp) == 0)
		return (sp);

	for (i = 0; i < ARRAY_LENGTH(sp) - 1; i++) {
		s = ARRAY_ITEM(sp, i, char *);
		if (s == NULL)
			continue;

		for (j = i + 1; j < ARRAY_LENGTH(sp); j++) {
			if (ARRAY_ITEM(sp, j, char *) == NULL)
				continue;

			if (strcmp(s, ARRAY_ITEM(sp, j, char *)) == 0)
				ARRAY_ITEM(sp, j, char *) = NULL;
		}
	}

	i = 0;
	while (i < ARRAY_LENGTH(sp)) {
		if (ARRAY_ITEM(sp, i, char *) == NULL)
			ARRAY_REMOVE(sp, i, char *);
		else
			i++;
	}

	return (sp);
}

char *
fmt_strings(const char *prefix, struct strings *sp)
{
	char	*buf, *s;
	size_t	 slen, len;
	ssize_t	 off;
	u_int	 i;

	if (ARRAY_LENGTH(sp) == 0) {
		if (prefix != NULL)
			return (xstrdup(prefix));
		return (xstrdup(""));
	}
	if (ARRAY_LENGTH(sp) == 1) {
		s = ARRAY_ITEM(sp, 0, char *);
		if (prefix != NULL)
			xasprintf(&buf, "%s\"%s\"", prefix, s);
		else
			xasprintf(&buf, "\"%s\"", s);
		return (buf);
	}

	len = BUFSIZ;
	buf = xmalloc(len);
	off = 0;
	if (prefix != NULL) {
		ENSURE_SIZE(buf, len, strlen(prefix));
		strlcpy(buf, prefix, len);
	}

	for (i = 0; i < ARRAY_LENGTH(sp); i++) {
		s = ARRAY_ITEM(sp, i, char *);
		slen = strlen(s);

		ENSURE_FOR(buf, len, off, slen + 4);
		xsnprintf(buf + off, len - off, "\"%s\" ", s);
		off += slen + 3;
	}

	buf[off - 1] = '\0';

	return (buf);

}

struct account *
find_account(char *name)
{
	struct account	*a;

	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (strcmp(a->name, name) == 0)
			return (a);
	}
	return (NULL);
}

int
have_accounts(char *name)
{
	struct account	*a;

	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (name_match(name, a->name))
			return (1);
	}

	return (0);
}

struct action *
find_action(char *name)
{
	struct action	*t;

	TAILQ_FOREACH(t, &conf.actions, entry) {
		if (strcmp(t->name, name) == 0)
			return (t);
	}
	return (NULL);
}

struct actions *
match_actions(char *name)
{
	struct action	*t;
	struct actions	*ta;

	ta = xmalloc(sizeof *ta);
	ARRAY_INIT(ta);

	TAILQ_FOREACH(t, &conf.actions, entry) {
		if (name_match(name, t->name))
			ARRAY_ADD(ta, t, struct action *);
	}

	return (ta);
}

struct macro *
find_macro(char *name)
{
	struct macro	*macro;

	TAILQ_FOREACH(macro, &macros, entry) {
		if (strcmp(macro->name, name) == 0)
			return (macro);
	}

	return (NULL);
}
%}

%token TOKALL TOKACCOUNT TOKSERVER TOKPORT TOKUSER TOKPASS TOKACTION
%token TOKSET TOKACCOUNTS TOKMATCH TOKIN TOKCONTINUE TOKSTDIN TOKPOP3 TOKPOP3S
%token TOKNONE TOKCASE TOKAND TOKOR TOKTO TOKACTIONS TOKHEADERS TOKBODY
%token TOKMAXSIZE TOKDELTOOBIG TOKLOCKTYPES TOKDEFUSER TOKDOMAIN TOKDOMAINS
%token TOKHEADER TOKFROMHEADERS TOKUSERS TOKMATCHED TOKUNMATCHED TOKNOT
%token TOKIMAP TOKIMAPS TOKDISABLED TOKFOLDER TOKPROXY TOKALLOWMANY TOKINCLUDE
%token TOKLOCKFILE TOKRETURNS TOKPIPE TOKSMTP TOKDROP TOKMAILDIR TOKMBOX
%token TOKWRITE TOKAPPEND TOKREWRITE TOKTAG TOKTAGGED TOKSIZE TOKMAILDIRS
%token TOKEXEC TOKSTRING TOKKEEP TOKIMPLACT TOKHOURS TOKMINUTES TOKSECONDS
%token TOKDAYS TOKWEEKS TOKMONTHS TOKYEARS TOKAGE TOKINVALID TOKKILOBYTES
%token TOKMEGABYTES TOKGIGABYTES TOKBYTES TOKATTACHMENT TOKCOUNT TOKTOTALSIZE
%token TOKANYTYPE TOKANYNAME TOKANYSIZE TOKEQ TOKNE TOKNNTP TOKCACHE TOKGROUP
%token TOKGROUPS TOKPURGEAFTER TOKCOMPRESS TOKNORECEIVED TOKFILEUMASK
%token TOKFILEGROUP TOKVALUE TOKTIMEOUT TOKREMOVEHEADER TOKSTDOUT
%token TOKADDFROM TOKAPPENDSTRING TOKADDHEADER
%token LCKFLOCK LCKFCNTL LCKDOTLOCK

%union
{
	long long 	 	 number;
        char 			*string;
	int 		 	 flag;
	u_int			 locks;
	struct {
		struct fetch	*fetch;
		void		*data;
	} fetch;
	struct {
		char		*host;
		char		*port;
	} server;
	struct {
		struct expr	*expr;
		enum ruletype	 type;
	} match;
	enum area	 	 area;
	enum exprop		 exprop;
	struct action	 	 action;
	struct expr		*expr;
	struct expritem		*expritem;
	struct strings		*strings;
	uid_t			 uid;
	gid_t			 gid;
	struct {
		struct strings	*users;
		int		 find_uid;
	} users;
	enum cmp		 cmp;
	struct rule		*rule;
	struct {
		char		*user;
		char		*pass;
	} userpass;
}

%token <number> NUMBER
%token <string> STRING STRMACRO STRMACROB NUMMACRO NUMMACROB

%type  <action> action
%type  <area> area
%type  <cmp> cmp cmp2
%type  <expr> expr exprlist
%type  <expritem> expritem
%type  <exprop> exprop
%type  <fetch> fetchtype
%type  <flag> cont icase not disabled keep poptype imaptype execpipe compress
%type  <flag> addfrom
%type  <gid> gid
%type  <locks> lock locklist
%type  <match> match
%type  <number> size time numv retrc
%type  <rule> perform
%type  <server> server
%type  <string> port to folder strv retre
%type  <strings> actions actionslist domains domainslist headers headerslist
%type  <strings> accounts accountslist pathslist maildirs groupslist groups
%type  <users> users userslist
%type  <userpass> userpass
%type  <uid> uid user

%%

/* Rules */

/** CMDS */
cmds: /* empty */
    | cmds account
    | cmds defaction
    | cmds defmacro
    | cmds include
    | cmds rule
    | cmds set
    | cmds close

/** STRV: <string> (char *) */
strv: STRING
      {
	      $$ = $1;
      }
    | STRMACRO
      {
	      struct macro	*macro;

	      if (strlen($1) > MAXNAMESIZE)
		      yyerror("macro name too long: %s", $1);

	      if ((macro = find_macro($1)) == NULL)
		      yyerror("undefined macro: %s", $1);
	      if (macro->type != MACRO_STRING)
		      yyerror("string macro expected: %s", $1);

	      $$ = xstrdup(macro->value.str);

	      xfree($1);
      }
    | STRMACROB
      {
	      struct macro	*macro;
	      char 		 name[MAXNAMESIZE];

	      if (strlen($1) > MAXNAMESIZE + 2)
		      yyerror("macro name too long: %s", $1);

	      name[0] = $1[0];
	      name[1] = '\0';
	      strlcat(name, $1 + 2, MAXNAMESIZE);
	      name[strlen(name) - 1] = '\0';

	      if ((macro = find_macro(name)) == NULL)
		      yyerror("undefined macro: %s", name);
	      if (macro->type != MACRO_STRING)
		      yyerror("string macro expected: %s", name);

	      $$ = xstrdup(macro->value.str);

	      xfree($1);
      }

/** NUMV: <number> (long long) */
numv: NUMBER
      {
	      $$ = $1;
      }
    | NUMMACRO
      {
	      struct macro	*macro;

	      if (strlen($1) > MAXNAMESIZE)
		      yyerror("macro name too long: %s", $1);

	      if ((macro = find_macro($1)) == NULL)
		      yyerror("undefined macro: %s", $1);
	      if (macro->type != MACRO_NUMBER)
		      yyerror("number macro expected: %s", $1);

	      $$ = macro->value.num;

	      xfree($1);
      }
    | NUMMACROB
      {
	      struct macro	*macro;
	      char 		 name[MAXNAMESIZE];

	      if (strlen($1) > MAXNAMESIZE + 2)
		      yyerror("macro name too long: %s", $1);

	      name[0] = $1[0];
	      name[1] = '\0';
	      strlcat(name, $1 + 2, MAXNAMESIZE);
	      name[strlen(name) - 1] = '\0';

	      if ((macro = find_macro(name)) == NULL)
		      yyerror("undefined macro: %s", name);
	      if (macro->type != MACRO_NUMBER)
		      yyerror("number macro expected: %s", name);

	      $$ = macro->value.num;

	      xfree($1);
      }

/** INCLUDE */
include: TOKINCLUDE strv
/**      [$2: strv (char *)] */
	 {
		 char			*path;
		 struct fileent		*top;

		 if (*$2 == '\0')
			 yyerror("invalid include file");

		 top = xmalloc(sizeof *top);
		 top->yyin = yyin;
		 top->yylineno = yylineno;
		 top->curfile = curfile;
		 ARRAY_ADD(&filestack, top, struct fileent *);

		 yyin = fopen($2, "r");
		 if (yyin == NULL) {
			 xasprintf(&path, "%s/%s", xdirname(conf.conf_file), $2);
			 if (access(path, R_OK) != 0)
				 yyerror("%s: %s", $2, strerror(errno));
			 yyin = fopen(path, "r");
			 if (yyin == NULL)
				 yyerror("%s: %s", path, strerror(errno));
			 curfile = path;
			 xfree($2);
		 } else
			 curfile = $2;
		 log_debug2("including file %s", curfile);
		 yyrestart(yyin);
		 yylineno = 0;
	 }

/** SIZE: <number> (long long) */
size: numv
/**   [$1: numv (long long)] */
      {
	      $$ = $1;
      }
    | numv TOKBYTES
/**   [$1: numv (long long)] */
      {
	      $$ = $1;
      }
    | numv TOKKILOBYTES
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / 1024)
		      yyerror("size is too big");
	      $$ = $1 * 1024;
      }
    | numv TOKMEGABYTES
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / (1024 * 1024))
		      yyerror("size is too big");
	      $$ = $1 * (1024 * 1024);
      }
    | numv TOKGIGABYTES
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / (1024 * 1024 * 1024))
		      yyerror("size is too big");
	      $$ = $1 * (1024 * 1024 * 1024);
      }

/** TIME: <number> (long long) */
time: numv
/**   [$1: numv (long long)] */
      {
	      $$ = $1;
      }
    | numv TOKHOURS
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / TIME_HOUR)
		      yyerror("time is too long");
	      $$ = $1 * TIME_HOUR;
      }
    | numv TOKMINUTES
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / TIME_MINUTE)
		      yyerror("time is too long");
	      $$ = $1 * TIME_MINUTE;
      }
    | numv TOKSECONDS
/**   [$1: numv (long long)] */
      {
	      $$ = $1;
      }
    | numv TOKDAYS
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / TIME_DAY)
		      yyerror("time is too long");
	      $$ = $1 * TIME_DAY;
      }
    | numv TOKWEEKS
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / TIME_WEEK)
		      yyerror("time is too long");
	      $$ = $1 * TIME_WEEK;
      }
    | numv TOKMONTHS
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / TIME_MONTH)
		      yyerror("time is too long");
	      $$ = $1 * TIME_MONTH;
      }
    | numv TOKYEARS
/**   [$1: numv (long long)] */
      {
	      if ($1 > LLONG_MAX / TIME_YEAR)
		      yyerror("time is too long");
	      $$ = $1 * TIME_YEAR;
      }

/** SET */
set: TOKSET TOKMAXSIZE size
/**  [$3: size (long long)] */
     {
	     if ($3 > MAXMAILSIZE)
		     yyerror("maximum size too large: %lld", $3);
	     conf.max_size = $3;
     }
   | TOKSET TOKLOCKTYPES locklist
/**  [$3: locklist (u_int)] */
     {
	     if ($3 & LOCK_FCNTL && $3 & LOCK_FLOCK)
		     yyerror("fcntl and flock locking cannot be used together");
	     conf.lock_types = $3;
     }
   | TOKSET TOKLOCKFILE strv
/**  [$3: strv (char *)] */
     {
	     if (conf.lock_file != NULL)
		     xfree(conf.lock_file);
	     conf.lock_file = $3;
     }
   | TOKSET TOKDELTOOBIG
     {
	     conf.del_big = 1;
     }
   | TOKSET TOKALLOWMANY
     {
	     conf.allow_many = 1;
     }
   | TOKSET TOKDEFUSER uid
/**  [$3: uid (uid_t)] */
     {
	     conf.def_user = $3;
     }
   | TOKSET TOKTIMEOUT time
/**  [$3: time (long long)] */
     {
	     if ($3 > INT_MAX / 1000)
		     yyerror("timeout too long: %lld", $3);
	     conf.timeout = $3;
     }
   | TOKSET domains
/**  [$2: domains (struct strings *)] */
     {
	     u_int	i;

	     if (conf.domains != NULL) {
		     for (i = 0; i < ARRAY_LENGTH(conf.domains); i++)
			     xfree(ARRAY_ITEM(conf.domains, i, void *));
		     ARRAY_FREE(conf.domains);
		     xfree(conf.domains);
	     }

	     conf.domains = $2;
     }
   | TOKSET headers
/**  [$2: headers (struct strings *)] */
     {
	     u_int	i;

	     if (conf.headers != NULL) {
		     for (i = 0; i < ARRAY_LENGTH(conf.headers); i++)
			     xfree(ARRAY_ITEM(conf.headers, i, void *));
		     ARRAY_FREE(conf.headers);
		     xfree(conf.headers);
	     }

	     conf.headers = $2;
     }
   | TOKSET TOKPROXY strv
/**  [$3: strv (char *)] */
     {
	     if (conf.proxy != NULL) {
		     xfree(conf.proxy->server.host);
		     xfree(conf.proxy->server.port);
		     if (conf.proxy->user != NULL)
			     xfree(conf.proxy->user);
		     if (conf.proxy->pass != NULL)
			     xfree(conf.proxy->pass);
	     }
	     if ((conf.proxy = getproxy($3)) == NULL)
		     yyerror("invalid proxy");
	     xfree($3);
     }
   | TOKSET TOKIMPLACT TOKKEEP
     {
	     conf.impl_act = DECISION_KEEP;
     }
   | TOKSET TOKIMPLACT TOKDROP
     {
	     conf.impl_act = DECISION_DROP;
     }
   | TOKSET TOKPURGEAFTER numv
/**  [$3: numv (long long)] */
     {
	     if ($3 == 0)
		     yyerror("invalid purge-after value: 0");
	     if ($3 > UINT_MAX)
		     yyerror("purge-after value too large: %lld", $3);

	     conf.purge_after = $3;
     }
   | TOKSET TOKPURGEAFTER TOKNONE
     {
	     conf.purge_after = 0;
     }
   | TOKSET TOKNORECEIVED
     {
	     conf.no_received = 1;
     }
   | TOKSET TOKFILEGROUP TOKUSER
     {
	     conf.file_group = NOGRP;
     }
   | TOKSET TOKFILEGROUP gid
/**  [$3: gid (gid_t)] */
     {
	     conf.file_group = $3;
     }
   | TOKSET TOKFILEUMASK TOKUSER
     {
	     conf.file_umask = umask(0);
	     umask(conf.file_umask);
     }
   | TOKSET TOKFILEUMASK numv
/**  [$3: numv (long long)] */
     {
	     char	s[8];
	     u_int	n;

	     /*
	      * We can't differentiate umasks in octal from normal numbers
	      * (requiring a leading zero a la C would be nice, but it would
	      * potentially break existing configs), so we need to fiddle to
	      * convert.
	      */
	     memset(s, 0, sizeof s);
	     xsnprintf(s, sizeof s, "%03lld", $3);
	     if (s[3] != '\0' || s[0] < '0' || s[0] > '7' ||
		 s[1] < 0 || s[1] > '7' || s[2] < '0' || s[2] > '7')
		     yyerror("invalid umask: %s", s);
	     if (sscanf(s, "%o", &n) != 1)
		     yyerror("invalid umask: %s", s);
	     conf.file_umask = n;
     }

/** DEFMACRO */
defmacro: STRMACRO '=' STRING
     	  {
		  struct macro	*macro;

		  if ((macro = find_macro($1)) == NULL) {
			  macro = xmalloc(sizeof *macro);
			  if (strlen($1) > MAXNAMESIZE)
				  yyerror("macro name too long: %s", $1);
			  macro->fixed = 0;
			  strlcpy(macro->name, $1, sizeof macro->name);
			  TAILQ_INSERT_HEAD(&macros, macro, entry);
		  }
		  if (!macro->fixed) {
			  macro->type = MACRO_STRING;
			  macro->value.str = $3;
			  log_debug3("added macro \"%s\": \"%s\"", macro->name,
			      macro->value.str);
			  xfree($1);
		  }
	  }
        | NUMMACRO '=' NUMBER
	  {
		  struct macro	*macro;

		  if ((macro = find_macro($1)) == NULL) {
			  macro = xmalloc(sizeof *macro);
			  if (strlen($1) > MAXNAMESIZE)
				  yyerror("macro name too long: %s", $1);
			  macro->fixed = 0;
			  strlcpy(macro->name, $1, sizeof macro->name);
			  TAILQ_INSERT_HEAD(&macros, macro, entry);
		  }
		  if (!macro->fixed) {
			  macro->type = MACRO_NUMBER;
			  macro->value.num = $3;
			  log_debug3("added macro \"%s\": %lld", macro->name,
			      macro->value.num);
			  xfree($1);
		  }
	  }

/** DOMAINS: <strings> (struct strings *) */
domains: TOKDOMAIN strv
/**      [$2: strv (char *)] */
	 {
		 char	*cp;

		 if (*$2 == '\0')
			 yyerror("invalid domain");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 for (cp = $2; *cp != '\0'; cp++)
			 *cp = tolower((int) *cp);
		 ARRAY_ADD($$, $2, char *);
	 }
       | TOKDOMAINS '{' domainslist '}'
/**      [$3: domainslist (struct strings *)] */
	 {
		 $$ = weed_strings($3);
	 }

/** DOMAINSLIST: <strings> (struct strings *) */
domainslist: domainslist strv
/**          [$1: domainslist (struct strings *)] [$2: strv (char *)] */
	     {
		     char	*cp;

		     if (*$2 == '\0')
			     yyerror("invalid domain");

		     $$ = $1;
		     for (cp = $2; *cp != '\0'; cp++)
			     *cp = tolower((int) *cp);
		     ARRAY_ADD($$, $2, char *);
	     }
	   | strv
/**          [$1: strv (char *)] */
	     {
		     char	*cp;

		     if (*$1 == '\0')
			     yyerror("invalid domain");

		     $$ = xmalloc(sizeof *$$);
		     ARRAY_INIT($$);
		     for (cp = $1; *cp != '\0'; cp++)
			     *cp = tolower((int) *cp);
		     ARRAY_ADD($$, $1, char *);
	     }

/** HEADERS: <strings> (struct strings *) */
headers: TOKHEADER strv
/**      [$2: strv (char *)] */
	 {
		 char	*cp;

		 if (*$2 == '\0')
			 yyerror("invalid header");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 for (cp = $2; *cp != '\0'; cp++)
			 *cp = tolower((int) *cp);
		 ARRAY_ADD($$, $2, char *);
	 }
       | TOKHEADERS '{' headerslist '}'
/**      [$3: headerslist (struct strings *)] */
	 {
		 $$ = weed_strings($3);
	 }

/** HEADERSLIST: <strings> (struct strings *) */
headerslist: headerslist strv
/**          [$1: headerslist (struct strings *)] [$2: strv (char *)] */
	     {
		     char	*cp;

		     if (*$2 == '\0')
			     yyerror("invalid header");

		     $$ = $1;
		     for (cp = $2; *cp != '\0'; cp++)
			     *cp = tolower((int) *cp);
		     ARRAY_ADD($$, $2, char *);
	     }
	   | strv
/**          [$1: strv (char *)] */
	     {
		     char	*cp;

		     if (*$1 == '\0')
			     yyerror("invalid header");

		     $$ = xmalloc(sizeof *$$);
		     ARRAY_INIT($$);
		     for (cp = $1; *cp != '\0'; cp++)
			     *cp = tolower((int) *cp);
		     ARRAY_ADD($$, $1, char *);
	     }

/** PATHSLIST: <strings> (struct strings *) */
pathslist: pathslist strv
/**        [$1: pathslist (struct strings *)] [$2: strv (char *)] */
	   {
		   if (*$2 == '\0')
			   yyerror("invalid path");

		   $$ = $1;
		   ARRAY_ADD($$, $2, char *);
	   }
	 | strv
/**        [$1: strv (char *)] */
	   {
		   if (*$1 == '\0')
			   yyerror("invalid path");

		   $$ = xmalloc(sizeof *$$);
		   ARRAY_INIT($$);
		   ARRAY_ADD($$, $1, char *);
	   }

/** MAILDIRS: <strings> (struct strings *) */
maildirs: TOKMAILDIR strv
/**       [$2: strv (char *)] */
	  {
		  if (*$2 == '\0')
			  yyerror("invalid path");

		  $$ = xmalloc(sizeof *$$);
		  ARRAY_INIT($$);
		  ARRAY_ADD($$, $2, char *);
	  }
        | TOKMAILDIRS '{' pathslist '}'
/**       [$3: pathslist (struct strings *)] */
	  {
		  $$ = weed_strings($3);
	  }

/** LOCK: <locks> (u_int) */
lock: LCKFCNTL
      {
	      $$ = LOCK_FCNTL;
      }
    | LCKFLOCK
      {
	      $$ = LOCK_FLOCK;
      }
    | LCKDOTLOCK
      {
	      $$ = LOCK_DOTLOCK;
      }

/** LOCKLIST: <locks> (u_int) */
locklist: locklist lock
/**       [$1: locklist (u_int)] [$2: lock (u_int)] */
	  {
		  $$ = $1 | $2;
	  }
	| lock
/**       [$1: lock (u_int)] */
	  {
		  $$ = $1;
	  }
	| TOKNONE
	  {
		  $$ = 0;
	  }

/** UID: <uid> (uid_t) */
uid: strv
/**  [$1: strv (char *)] */
     {
	     struct passwd	*pw;

	     pw = getpwnam($1);
	     if (pw == NULL)
		     yyerror("unknown user: %s", $1);
	     $$ = pw->pw_uid;
	     endpwent();

	     xfree($1);
     }
   | numv
/**  [$1: numv (long long)] */
     {
	     struct passwd	*pw;

	     if ($1 > UID_MAX)
		     yyerror("invalid uid: %llu", $1);
	     pw = getpwuid($1);
	     if (pw == NULL)
		     yyerror("unknown uid: %llu", $1);
	     $$ = pw->pw_uid;
	     endpwent();
     }

/** GID: <gid> (gid_t) */
gid: strv
/**  [$1: strv (char *)] */
     {
	     struct group	*gr;

	     gr = getgrnam($1);
	     if (gr == NULL)
		     yyerror("unknown group: %s", $1);
	     $$ = gr->gr_gid;
	     endgrent();

	     xfree($1);
     }
   | numv
/**  [$1: numv (long long)] */
     {
	     struct group	*gr;

	     if ($1 > GID_MAX)
		     yyerror("invalid gid: %llu", $1);
	     gr = getgrgid($1);
	     if (gr == NULL)
		     yyerror("unknown gid: %llu", $1);
	     $$ = gr->gr_gid;
	     endgrent();
     }

/** USER: <uid> (uid_t) */
user: /* empty */
      {
	      $$ = 0;
      }
    | TOKUSER uid
/**   [$2: uid (uid_t)] */
      {
	      $$ = $2;
      }


/** USERS: <users> (struct { ... } users) */
users: /* empty */
       {
	       $$.users = NULL;
	       $$.find_uid = 0;
       }
     | TOKUSER TOKFROMHEADERS
       {
	       $$.users = NULL;
	       $$.find_uid = 1;
       }
     | TOKUSERS TOKFROMHEADERS
       {
	       $$.users = NULL;
	       $$.find_uid = 1;
       }
     | TOKUSER uid
/**    [$2: uid (uid_t)] */
       {
	       $$.users = xmalloc(sizeof *$$.users);
	       ARRAY_INIT($$.users);
	       ARRAY_ADD($$.users, $2, uid_t);
	       $$.find_uid = 0;
       }
     | TOKUSERS '{' userslist '}'
/**    [$3: userslist (struct { ... } users)] */
       {
	       $$ = $3;
	       $$.users = weed_strings($$.users);
	       $$.find_uid = 0;
       }

/** USERSLIST: <users> (struct { ... } users) */
userslist: userslist uid
/**        [$1: userslist (struct { ... } users)] [$2: uid (uid_t)] */
	   {
		   $$ = $1;
		   ARRAY_ADD($$.users, $2, uid_t);
	   }
	 | uid
/**        [$1: uid (uid_t)] */
	   {
		   $$.users = xmalloc(sizeof *$$.users);
		   ARRAY_INIT($$.users);
		   ARRAY_ADD($$.users, $1, uid_t);
	   }

/** ICASE: <flag> (int) */
icase: TOKCASE
      {
	      /* match case */
	      $$ = 0;
      }
    | /* empty */
      {
	      /* ignore case */
	      $$ = 1;
      }

/** NOT: <flag> (int) */
not: TOKNOT
      {
	      $$ = 1;
      }
    | /* empty */
      {
	      $$ = 0;
      }

/** KEEP: <flag> (int) */
keep: TOKKEEP
      {
	      $$ = 1;
      }
    | /* empty */
      {
	      $$ = 0;
      }

/** DISABLED: <flag> (int) */
disabled: TOKDISABLED
          {
		  $$ = 1;
          }
        | /* empty */
	  {
		  $$ = 0;
	  }

/** PORT: <string> (char *) */
port: TOKPORT strv
/**   [$2: strv (char *)] */
      {
	      if (*$2 == '\0')
		      yyerror("invalid port");

	      $$ = $2;
      }
    | TOKPORT numv
/**   [$2: numv (long long)] */
      {
	      if ($2 == 0 || $2 > 65535)
		      yyerror("invalid port");

	      xasprintf(&$$, "%lld", $2);
      }

/** SERVER: <server> (struct { ... } server) */
server: TOKSERVER strv port
/**     [$2: strv (char *)] [$3: port (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid host");

		$$.host = $2;
		$$.port = $3;
	}
      | TOKSERVER strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid host");

		$$.host = $2;
		$$.port = NULL;
	}

/** TO: <string> (char *) */
to: /* empty */
    {
	    $$ = NULL;
    }
  | TOKTO strv
/**  [$2: strv (char *)] */
    {
	    $$ = $2;
    }

/** COMPRESS: <flag> (int) */
compress: TOKCOMPRESS
	  {
		  $$ = 1;
	  }
	| /* empty */
	  {
		  $$ = 0;
	  }

/** ADDFROM: <flag> (int) */
addfrom: TOKADDFROM
	 {
		 $$ = 1;
	 }
       | /* empty */
	 {
		 $$ = 0;
	 }

/** ACTION: <action> (struct action) */
action: TOKPIPE strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid command");

		$$.deliver = &deliver_pipe;

		$$.data = $2;
	}
      | TOKEXEC strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid command");

		$$.deliver = &deliver_exec;

		$$.data = $2;
	}
      | TOKREWRITE strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid command");

		$$.deliver = &deliver_rewrite;

		$$.data = $2;
	}
      | TOKWRITE strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_write;

		$$.data = $2;
	}
      | TOKAPPEND strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_append;

		$$.data = $2;
	}
      | TOKMAILDIR strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_maildir;

		$$.data = $2;
	}
      | TOKREMOVEHEADER strv
/**     [$2: strv (char *)] */
	{
		char	*cp;

		if (*$2 == '\0')
			yyerror("invalid header");

		$$.deliver = &deliver_remove_header;

		for (cp = $2; *cp != '\0'; cp++)
			*cp = tolower((int) *cp);
		$$.data = $2;
	}
      | TOKADDHEADER strv strv
/**     [$2: strv (char *)] [$3: strv (char *)] */
	{
		struct deliver_add_header_data	*data;

		if (*$2 == '\0')
			yyerror("invalid header");

		$$.deliver = &deliver_add_header;

		data = xcalloc(1, sizeof *data);
		$$.data = data;

		data->hdr = $2;
		data->value = $3;
	}
      | TOKAPPENDSTRING strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid string");

		$$.deliver = &deliver_append_string;

		$$.data = $2;
	}
      | TOKMBOX strv compress
/**     [$2: strv (char *)] [$3: compress (int)] */
	{
		struct deliver_mbox_data	*data;

		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_mbox;

		data = xcalloc(1, sizeof *data);
		$$.data = data;

		data->path = $2;
		data->compress = $3;
	}
      | TOKSMTP server to
/**     [$2: server (struct { ... } server)] [$3: to (char *)] */
	{
		struct deliver_smtp_data	*data;

		$$.deliver = &deliver_smtp;

		data = xcalloc(1, sizeof *data);
		$$.data = data;

		data->server.host = $2.host;
		data->server.port = $2.port != NULL ? $2.port : xstrdup("smtp");
		data->server.ai = NULL;
		data->to = $3;
	}
      | TOKSTDOUT addfrom
/**     [$2: addfrom (int)] */
	{
		struct deliver_stdout_data	*data;

		$$.deliver = &deliver_stdout;

		data = xcalloc(1, sizeof *data);
		$$.data = data;

		data->add_from = $2;
	}
      | TOKDROP
        {
		$$.deliver = &deliver_drop;
	}
      | TOKKEEP
        {
		$$.deliver = &deliver_keep;
	}

/** DEFACTION */
defaction: TOKACTION strv users action
/**        [$2: strv (char *)] [$3: users (struct { ... } users)] */
/**        [$4: action (struct action)] */
	   {
		   struct action	*t;
		   char			 desc[DESCBUFSIZE];

		   if (strlen($2) >= MAXNAMESIZE)
			   yyerror("action name too long: %s", $2);
		   if (*$2 == '\0')
			   yyerror("invalid action name");
		   if (find_action($2) != NULL)
			   yyerror("duplicate action: %s", $2);

		   t = xmalloc(sizeof *t);
		   memcpy(t, &$4, sizeof *t);
		   strlcpy(t->name, $2, sizeof t->name);
		   t->users = $3.users;
		   t->find_uid = $3.find_uid;
		   TAILQ_INSERT_TAIL(&conf.actions, t, entry);

		   t->deliver->desc(t, desc, sizeof desc);
		   log_debug2("added action \"%s\": deliver=%s", t->name, desc);

		   xfree($2);
	   }

/** ACCOUNTS: <strings> (struct strings *) */
accounts: /* empty */
	  {
		  $$ = NULL;
	  }
        | TOKACCOUNT strv
/**       [$2: strv (char *)] */
	  {
		  if (*$2 == '\0')
			  yyerror("invalid account name");
		  if (!have_accounts($2))
			  yyerror("no matching accounts: %s", $2);

		  $$ = xmalloc(sizeof *$$);
		  ARRAY_INIT($$);
		  ARRAY_ADD($$, $2, char *);
	  }
	| TOKACCOUNTS '{' accountslist '}'
/**       [$3: accountslist (struct strings *)] */
	  {
		  $$ = weed_strings($3);
	  }

/** ACCOUNTSLIST: <strings> (struct strings *) */
accountslist: accountslist strv
/**           [$1: accountslist (struct strings *)] [$2: strv (char *)] */
 	      {
		      if (*$2 == '\0')
			      yyerror("invalid account name");
		      if (!have_accounts($2))
			      yyerror("no matching accounts: %s", $2);

		      $$ = $1;
		      ARRAY_ADD($$, $2, char *);
	      }
	    | strv
/**           [$1: strv (char *)] */
	      {
		      if (*$1 == '\0')
			      yyerror("invalid account name");
		      if (!have_accounts($1))
			      yyerror("no matching accounts: %s", $1);

		      $$ = xmalloc(sizeof *$$);
		      ARRAY_INIT($$);
		      ARRAY_ADD($$, $1, char *);
	      }

/** ACTIONS: <strings> (struct strings *) */
actions: TOKACTION TOKNONE
	 {
		 $$ = NULL;
	 }
       | TOKACTION strv
/**      [$2: strv (char *)] */
	 {
		 if (*$2 == '\0')
			 yyerror("invalid action name");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_ADD($$, $2, char *);
	 }
       | TOKACTIONS '{' actionslist '}'
/**      [$3: actionslist (struct strings *)] */
         {
		 $$ = $3;
	 }

/** ACTIONSLIST: <strings> (struct strings *) */
actionslist: actionslist strv
/**          [$1: actionslist (struct strings *)] [$2: strv (char *)] */
	     {
		     if (*$2 == '\0')
			     yyerror("invalid action name");

		     $$ = $1;
		     ARRAY_ADD($$, $2, char *);
	     }
	   | strv
/**          [$1: strv (char *)] */
	     {
		     if (*$1 == '\0')
			     yyerror("invalid action name");

		     $$ = xmalloc(sizeof *$$);
		     ARRAY_INIT($$);
		     ARRAY_ADD($$, $1, char *);
	     }

/** CONT: <flag> (int) */
cont: /* empty */
      {
	      $$ = 0;
      }
    | TOKCONTINUE
      {
	      $$ = 1;
      }

/** AREA: <area> (enum area) */
area: /* empty */
      {
	      $$ = AREA_ANY;
      }
    | TOKIN TOKALL
      {
	      $$ = AREA_ANY;
      }
    | TOKIN TOKHEADERS
      {
	      $$ = AREA_HEADERS;
      }
    | TOKIN TOKBODY
      {
	      $$ = AREA_BODY;
      }

/** RETRC: <number> (long long) */
retrc: numv
/**    [$1: numv (long long)] */
       {
	       if ($1 < 0 || $1 > 255)
		       yyerror("invalid return code");

	       $$ = $1;
       }
     | /* empty */
       {
	       $$ = -1;
       }

/** RETRE: <string> (char *) */
retre: strv
/**    [$1: strv (char *)] */
       {
	       if (*$1 == '\0')
		       yyerror("invalid regexp");

	       $$ = $1;
       }
     | /* empty */
       {
	       $$ = NULL;
       }

/** CMP: <cmp> (enum cmp) */
cmp: '<'
     {
	     $$ = CMP_LT;
     }
   | '>'
     {
	     $$ = CMP_GT;
     }

/** CMP2: <cmp> (enum cmp) */
cmp2: cmp
/**   [$1: cmp (enum cmp)] */
      {
	     $$ = $1;
      }
    | TOKEQ
      {
	      $$ = CMP_EQ;
      }
    | TOKNE
      {
	      $$ = CMP_NE;
      }

/** EXECPIPE: <flag> (int) */
execpipe: TOKEXEC
	  {
		  $$ = 0;
	  }
        | TOKPIPE
	  {
		  $$ = 1;
	  }

/** EXPROP: <exprop> (enum exprop) */
exprop: TOKAND
	{
		$$ = OP_AND;
        }
      | TOKOR
	{
		$$ = OP_OR;
	}

/** EXPRITEM: <expritem> (struct expritem *) */
expritem: not icase strv area
/**       [$1: not (int)] [$2: icase (int)] [$3: strv (char *)] */
/**       [$4: area (enum area)] */
          {
		  struct match_regexp_data	*data;
		  int	 			 flags;
		  char				*cause;

		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_regexp;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->area = $4;

		  flags = REG_EXTENDED|REG_NEWLINE;
		  if ($2)
			  flags |= REG_ICASE;
		  if (re_compile(&data->re, $3, flags, &cause) != 0)
			  yyerror("%s", cause);
	  }
        | not execpipe strv user TOKRETURNS '(' retrc ',' retre ')'
/**       [$1: not (int)] [$2: execpipe (int)] [$3: strv (char *)] */
/**       [$4: user (uid_t)] [$7: retrc (long long)] [$9: retre (char *)] */
	  {
		  struct match_command_data	*data;
		  int	 			 flags;
		  char				*cause;

		  if (*$3 == '\0' || ($3[0] == '|' && $3[1] == '\0'))
			  yyerror("invalid command");
		  if ($7 == -1 && $9 == NULL)
			  yyerror("return code or regexp must be specified");

		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_command;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->uid = $4;
		  data->pipe = $2;
		  data->cmd = $3;

		  data->ret = $7;

		  if ($9 != NULL) {
			  flags = REG_EXTENDED|REG_NEWLINE;
			  if (re_compile(&data->re, $9, flags, &cause) != 0)
				  yyerror("%s", cause);
		  }

	  }
	| not TOKTAGGED strv
/**       [$1: not (int)] [$3: strv (char *)] */
	  {
		  struct match_tagged_data	*data;

		  if (*$3 == '\0')
			  yyerror("invalid tag");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_tagged;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->tag = $3;
	  }
        | not TOKSIZE cmp size
/**       [$1: not (int)] [$3: cmp (enum cmp)] [$4: size (long long)] */
	  {
		  struct match_size_data	*data;

#if SIZE_MAX < LLONG_MAX
		  if ($4 > SIZE_MAX)
			  yyerror("size too large");
#endif

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_size;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->size = $4;
		  data->cmp = $3;
	  }
        | not TOKSTRING strv TOKTO strv
/**       [$1: not (int)] [$3: strv (char *)] [$5: strv (char *)] */
	  {
		  struct match_string_data	*data;
		  int	 			 flags;
		  char				*cause;

		  if (*$3 == '\0')
			  yyerror("invalid string");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_string;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->str = $3;

		  flags = REG_EXTENDED|REG_NOSUB|REG_NEWLINE;
		  if (re_compile(&data->re, $5, flags, &cause) != 0)
			  yyerror("%s", cause);
	  }
        | not TOKMATCHED
/**       [$1: not (int)] */
	  {
		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_matched;
		  $$->inverted = $1;
          }
        | not TOKUNMATCHED
/**       [$1: not (int)] */
	  {
		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_unmatched;
		  $$->inverted = $1;
          }
        | not TOKAGE cmp time
/**       [$1: not (int)] [$3: cmp (enum cmp)] [$4: time (long long)] */
	  {
		  struct match_age_data	*data;

		  if ($4 == 0)
			  yyerror("invalid time");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_age;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->time = $4;
		  data->cmp = $3;
	  }
        | not TOKAGE TOKINVALID
/**       [$1: not (int)] */
	  {
		  struct match_age_data	*data;

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_age;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->time = -1;
	  }
        | not TOKATTACHMENT TOKCOUNT cmp2 numv
/**       [$1: not (int)] [$4: cmp2 (enum cmp)] [$5: numv (long long)] */
	  {
		  struct match_attachment_data	*data;

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_attachment;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->op = ATTACHOP_COUNT;
		  data->cmp = $4;
		  data->value.num = $5;
	  }
        | not TOKATTACHMENT TOKTOTALSIZE cmp size
/**       [$1: not (int)] [$4: cmp (enum cmp)] [$5: size (long long)] */
	  {
		  struct match_attachment_data	*data;

#if SIZE_MAX < LLONG_MAX
		  if ($5 > SIZE_MAX)
			  yyerror("size too large");
#endif

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_attachment;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->op = ATTACHOP_TOTALSIZE;
		  data->cmp = $4;
		  data->value.size = $5;
	  }
        | not TOKATTACHMENT TOKANYSIZE cmp size
/**       [$1: not (int)] [$4: cmp (enum cmp)] [$5: size (long long)] */
	  {
		  struct match_attachment_data	*data;

#if SIZE_MAX < LLONG_MAX
		  if ($5 > SIZE_MAX)
			  yyerror("size too large");
#endif

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_attachment;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->op = ATTACHOP_ANYSIZE;
		  data->cmp = $4;
		  data->value.size = $5;
	  }
        | not TOKATTACHMENT TOKANYTYPE strv
/**       [$1: not (int)] [$4: strv (char *)] */
	  {
		  struct match_attachment_data	*data;

		  if (*$4 == '\0')
			  yyerror("invalid string");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_attachment;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->op = ATTACHOP_ANYTYPE;
		  data->value.str = $4;
	  }
        | not TOKATTACHMENT TOKANYNAME strv
/**       [$1: not (int)] [$4: strv (char *)] */
	  {
		  struct match_attachment_data	*data;

		  if (*$4 == '\0')
			  yyerror("invalid string");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_attachment;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->op = ATTACHOP_ANYNAME;
		  data->value.str = $4;
	  }


/** EXPRLIST: <expr> (struct expr *) */
exprlist: exprlist exprop expritem
/**       [$1: exprlist (struct expr *)] [$2: exprop (enum exprop)] */
/**       [$3: expritem (struct expritem *)] */
	  {
		  $$ = $1;

		  $3->op = $2;
		  TAILQ_INSERT_TAIL($$, $3, entry);
	  }
        | exprop expritem
/**       [$1: exprop (enum exprop)] [$2: expritem (struct expritem *)] */
	  {
		  $$ = xmalloc(sizeof *$$);
		  TAILQ_INIT($$);

		  $2->op = $1;
		  TAILQ_INSERT_HEAD($$, $2, entry);
	  }

/** EXPR: <expr> (struct expr *) */
expr: expritem
/**   [$1: expritem (struct expritem *)] */
      {
	      $$ = xmalloc(sizeof *$$);
	      TAILQ_INIT($$);

	      TAILQ_INSERT_HEAD($$, $1, entry);
      }
    | expritem exprlist
/**   [$1: expritem (struct expritem *)] [$2: exprlist (struct expr *)] */
      {
	      $$ = $2;

	      TAILQ_INSERT_HEAD($$, $1, entry);
      }

/** MATCH: <match> (struct { ... } match) */
match: TOKMATCH expr
/**    [$2: expr (struct expr *)] */
       {
	       $$.expr = $2;
	       $$.type = RULE_EXPRESSION;
       }
     | TOKMATCH TOKALL
       {
	       $$.expr = NULL;
	       $$.type = RULE_ALL;
       }

/** PERFORM: <rule> (struct rule *) */
perform: TOKTAG strv
/**      [$2: strv (char *)] */
	 {
		 if (*$2 == '\0')
			 yyerror("invalid tag");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = ruleidx++;
		 $$->actions = NULL;
		 $$->key = $2;
		 $$->value = xstrdup("");
		 TAILQ_INIT(&$$->rules);
		 $$->stop = 0;
		 $$->users = NULL;
		 $$->find_uid = 0;

		 if (currule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&currule->rules, $$, entry);
	 }
       | TOKTAG strv TOKVALUE strv
/**      [$2: strv (char *)] [$4: strv (char *)] */
	 {
		 if (*$2 == '\0')
			 yyerror("invalid tag");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = ruleidx++;
		 $$->actions = NULL;
		 $$->key = $2;
		 $$->value = $4;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = 0;
		 $$->users = NULL;
		 $$->find_uid = 0;

		 if (currule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&currule->rules, $$, entry);
	 }
       | users actions cont
/**      [$1: users (struct { ... } users)] */
/**      [$2: actions (struct strings *)] [$3: cont (int)] */
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = ruleidx++;
		 $$->actions = $2;
		 $$->key = NULL;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = !$3;
		 $$->users = $1.users;
		 $$->find_uid = $1.find_uid;

		 if (currule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&currule->rules, $$, entry);
	 }
       | '{'
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = ruleidx++;
		 $$->actions = NULL;
		 $$->key = NULL;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = 0;
		 $$->users = NULL;
		 $$->find_uid = 0;

		 if (currule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&currule->rules, $$, entry);

		 ARRAY_ADD(&rulestack, currule, struct rule *);
		 currule = $$;
	 }

/** CLOSE */
close: '}'
       {
	       if (currule == NULL)
		       yyerror("missing {");

	       currule = ARRAY_LAST(&rulestack, struct rule *);
	       ARRAY_TRUNC(&rulestack, 1, struct rule *);
       }

/** RULE */
rule: match accounts perform
/**   [$1: match (struct { ... } match)] [$2: accounts (struct strings *)] */
/**   [$3: perform (struct rule *)] */
      {
	      struct expritem	*ei;
	      char		 s[1024], *sa, *ss, desc[DESCBUFSIZE];
	      size_t		 off;

	      $3->accounts = $2;
	      $3->expr = $1.expr;
	      $3->type = $1.type;

	      switch ($3->type) {
 	      case RULE_ALL:
		      strlcpy(s, "all", sizeof s);
		      break;
	      case RULE_EXPRESSION:
		      *s = '\0';
		      off = 0;
		      TAILQ_FOREACH(ei, $3->expr, entry) {
			      if (ei->inverted)
				      off = strlcat(s, "not ", sizeof s);
			      switch (ei->op) {
			      case OP_AND:
				      strlcat(s, "and ", sizeof s);
				      break;
			      case OP_OR:
				      strlcat(s, "or ", sizeof s);
				      break;
			      case OP_NONE:
				      break;
			      }
			      ei->match->desc(ei, desc, sizeof desc);
			      strlcat(s, desc, sizeof s);
			      strlcat(s, " ", sizeof s);
		      }
		      break;
	      }
	      if ($3->accounts != NULL)
		      sa = fmt_strings(" accounts=", $3->accounts);
	      else
		      sa = xstrdup("");
	      if ($3->actions != NULL) {
		      ss = fmt_strings(NULL, $3->actions);
		      log_debug2("added rule %u:%s actions=%s matches=%s",
			  $3->idx, sa, ss, s);
		      xfree(ss);
	      } else if ($3->key != NULL) {
		      log_debug2("added rule %u:%s tag=%s (%s) matches=%s",
			  $3->idx, sa, $3->key, $3->value, s);
	      } else {
		      log_debug2("added rule %u:%s nested matches=%s",
			  $3->idx, sa, s);
	      }
	      xfree(sa);
      }

/** FOLDER: <string> (char *) */
folder: /* empty */
        {
		$$ = NULL;
        }
      | TOKFOLDER strv
/**     [$2: strv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid folder");

		$$ = $2;
	}

/** GROUPSLIST: <strings> (struct strings *) */
groupslist: groupslist strv
/**         [$1: groupslist (struct strings *)] [$2: strv (char *)] */
 	    {
		    char		*cp;

		    if (*$2 == '\0')
			    yyerror("invalid group");

		    $$ = $1;

		    for (cp = $2; *cp != '\0'; cp++)
			    *cp = tolower((int) *cp);

		    ARRAY_ADD($$, $2, char *);
	    }
	  | strv
/**         [$1: strv (char *)] */
	    {
		    char		*cp;

		    if (*$1 == '\0')
			    yyerror("invalid group");

		    $$ = xmalloc(sizeof *$$);
		    ARRAY_INIT($$);

		    for (cp = $1; *cp != '\0'; cp++)
			    *cp = tolower((int) *cp);

		    ARRAY_ADD($$, $1, char *);
	    }

/** GROUPS: <strings> (struct strings *) */
groups: TOKGROUP strv
/**     [$2: strv (char *)] */
	{
		char			*cp;

		if (*$2 == '\0')
			yyerror("invalid group");

		$$ = xmalloc(sizeof *$$);
		ARRAY_INIT($$);

		for (cp = $2; *cp != '\0'; cp++)
			*cp = tolower((int) *cp);

		ARRAY_ADD($$, $2, char *);
	}
      | TOKGROUPS '{' groupslist '}'
/**     [$3: groupslist (struct strings *)] */
        {
		$$ = weed_strings($3);
	}

/** POPTYPE: <flag> (int) */
poptype: TOKPOP3
         {
		 $$ = FETCHPORT_NORMAL;
         }
       | TOKPOP3S
	 {
		 $$ = FETCHPORT_SSL;
	 }

/** IMAPTYPE: <flag> (int) */
imaptype: TOKIMAP
          {
		  $$ = FETCHPORT_NORMAL;
          }
        | TOKIMAPS
	  {
		  $$ = FETCHPORT_SSL;
	  }

/** USERPASS: <userpass> (struct { ... } userpass) */
userpass: TOKUSER strv TOKPASS strv
/**       [$2: strv (char *)] [$4: strv (char *)] */
	  {
		   if (*$2 == '\0')
			   yyerror("invalid user");
		   if (*$4 == '\0')
			   yyerror("invalid pass");

		  $$.user = $2;
		  $$.pass = $4;
	  }
	| /* empty */
	  {
		  $$.user = NULL;
		  $$.pass = NULL;
	  }

/** FETCHTYPE: <fetch> (struct { ... } fetch) */
fetchtype: poptype server TOKUSER strv TOKPASS strv
/**        [$1: poptype (int)] [$2: server (struct { ... } server)] */
/**        [$4: strv (char *)] [$6: strv (char *)] */
           {
		   struct fetch_pop3_data	*data;

		   if (*$4 == '\0')
			   yyerror("invalid user");
		   if (*$6 == '\0')
			   yyerror("invalid pass");

		   $$.fetch = &fetch_pop3;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->user = $4;
		   data->pass = $6;
		   data->server.ssl = $1;
		   data->server.host = $2.host;
		   if ($2.port != NULL)
			   data->server.port = $2.port;
		   else
			   data->server.port = xstrdup($$.fetch->ports[$1]);
		   data->server.ai = NULL;
	   }
         | imaptype server TOKUSER strv TOKPASS strv folder
/**        [$1: imaptype (int)] [$2: server (struct { ... } server)] */
/**        [$4: strv (char *)] [$6: strv (char *)] [$7: folder (char *)] */
           {
		   struct fetch_imap_data	*data;

		   if (*$4 == '\0')
			   yyerror("invalid user");
		   if (*$6 == '\0')
			   yyerror("invalid pass");
		   if ($7 != NULL && *$7 == '\0')
			   yyerror("invalid folder");

		   $$.fetch = &fetch_imap;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->user = $4;
		   data->pass = $6;
		   data->folder = $7 == NULL ? xstrdup("INBOX") : $7;
		   data->server.ssl = $1;
		   data->server.host = $2.host;
		   if ($2.port != NULL)
			   data->server.port = $2.port;
		   else
			   data->server.port = xstrdup($$.fetch->ports[$1]);
		   data->server.ai = NULL;
	   }
	 | TOKIMAP TOKPIPE strv userpass folder
/**        [$3: strv (char *)] */
/**        [$4: userpass (struct { ... } userpass)] [$5: folder (char *)] */
	   {
		   struct fetch_imap_data	*data;
		   struct strb			*tags;

		   if ($5 != NULL && *$5 == '\0')
			   yyerror("invalid folder");

		   $$.fetch = &fetch_imappipe;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->user = $4.user;
		   data->pass = $4.pass;
		   data->folder = $5 == NULL ? xstrdup("INBOX") : $5;
		   strb_create(&tags);
		   default_tags(&tags, NULL, NULL);
		   data->pipecmd = replace($5, tags, NULL, 0, NULL);
		   strb_destroy(&tags);
		   if (data->pipecmd == NULL || *data->pipecmd == '\0')
			   yyerror("invalid pipe command");
	   }
	 | TOKSTDIN
	   {
		   struct fetch_stdin_data	*data;

		   $$.fetch = &fetch_stdin;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
	   }
         | maildirs
/**        [$1: maildirs (struct strings *)] */
	   {
		   struct fetch_maildir_data	*data;

		   $$.fetch = &fetch_maildir;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->maildirs = $1;
	   }
	 | TOKNNTP server groups TOKCACHE strv
/**        [$2: server (struct { ... } server)] */
/**        [$3: groups (struct strings *)] [$5: strv (char *)] */
           {
		   struct fetch_nntp_data	*data;
		   char				*group;
		   struct strb		*tags;

		   if (*$5 == '\0')
			   yyerror("invalid cache");

		   $$.fetch = &fetch_nntp;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->names = $3;

		   if (ARRAY_LENGTH($3) == 1)
			   group = ARRAY_ITEM($3, 0, char *);
		   else
			   group = NULL;
		   strb_create(&tags);
		   default_tags(&tags, group, NULL);
		   data->path = replace($5, tags, NULL, 0, NULL);
		   strb_destroy(&tags);
		   if (data->path == NULL || *data->path == '\0')
			   yyerror("invalid cache");
		   xfree($5);

		   data->server.host = $2.host;
		   if ($2.port != NULL)
			   data->server.port = $2.port;
		   else
			   data->server.port = xstrdup($$.fetch->ports[0]);
		   data->server.ai = NULL;
	   }

/** ACCOUNT */
account: TOKACCOUNT strv disabled users fetchtype keep
/**      [$2: strv (char *)] [$3: disabled (int)] */
/**      [$4: users (struct { ... } users)] [$5: fetchtype (struct { ... } fetch)] */
/**      [$6: keep (int)] */
         {
		 struct account		*a;
		 char			 desc[DESCBUFSIZE]
;
		 if (strlen($2) >= MAXNAMESIZE)
			 yyerror("account name too long: %s", $2);
		 if (*$2 == '\0')
			 yyerror("invalid account name");
		 if (find_account($2) != NULL)
			 yyerror("duplicate account: %s", $2);

		 a = xcalloc(1, sizeof *a);
		 strlcpy(a->name, $2, sizeof a->name);
		 a->keep = $6;
		 a->disabled = $3;
		 a->users = $4.users;
		 a->find_uid = $4.find_uid;
		 a->fetch = $5.fetch;
		 a->data = $5.data;
		 TAILQ_INSERT_TAIL(&conf.accounts, a, entry);

		 a->fetch->desc(a, desc, sizeof desc);
		 log_debug2("added account \"%s\": fetch=%s", a->name, desc);
	 }

%%

/* Programs */
