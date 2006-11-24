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

#include <ctype.h>
#include <fnmatch.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "fdm.h"

struct macros	macros = TAILQ_HEAD_INITIALIZER(macros);

struct filestackent {
	FILE				*yyin;
	int		 	 	 yylineno;
	char				*curfile;
};
ARRAY_DECLARE(, struct filestackent *)	 filestack;
char					*curfile;

ARRAY_DECLARE(, struct rule *)		 rulestack;
struct rule				*currule;

extern FILE			*yyin;
extern int		 	 yylineno;
extern int 		 	 yylex(void);
extern void		 	 yyrestart(FILE *);

int			 	 yyparse(void);
__dead printflike1 void  	 yyerror(const char *, ...);
int 			 	 yywrap(void);

struct account 			*find_account(char *);

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
	struct filestackent	*top;
	char			*file;

	file = curfile == NULL ? conf.conf_file : curfile;
	log_debug2("finished file %s", file);

	if (ARRAY_EMPTY(&filestack)) {
		while (!TAILQ_EMPTY(&macros)) {
			macro = TAILQ_FIRST(&macros);
			TAILQ_REMOVE(&macros, macro, entry);
			if (macro->type == MACRO_STRING)
				xfree(macro->value.string);
			xfree(macro);
		}

		ARRAY_FREE(&filestack);
		if (!ARRAY_EMPTY(&rulestack))
			yyerror("missing }");
		ARRAY_FREE(&rulestack);
		return (1);
	}

	top = ARRAY_LAST(&filestack, struct filestackent *);
	yyin = top->yyin;
	yyrestart(yyin);
	yylineno = top->yylineno;
	xfree(curfile);
	curfile = top->curfile;
	xfree(top);
	ARRAY_TRUNC(&filestack, 1, struct filestackent *);

        return (0);
}

struct account *
find_account(char *name)
{
	struct account	*a;

	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (name_match(name, a->name))
			return (a);
	}
	return (NULL);
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

struct actionptrs *
find_actions(char *name)
{
	struct action		*t;
	struct actionptrs	*ta;

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
%token TOKWRITE TOKAPPEND TOKREWRITE TOKTAG TOKTAGGED TOKEQ TOKNE TOKSIZE
%token TOKEXEC TOKSTRING TOKKEEP TOKIMPLACT TOKHOURS TOKMINUTES TOKSECONDS
%token TOKDAYS TOKWEEKS TOKMONTHS TOKYEARS TOKAGE TOKINVALID 
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
	struct accounts		*accounts;
	struct action	 	 action;
	struct actionnames	*actions;
	struct domains		*domains;
	struct headers	 	*headers;
	enum exprop		 exprop;
	struct expritem		*expritem;
	struct expr		*expr;
	uid_t			 uid;
	struct {
		struct users	*users;
		int		 find_uid;
	} users;
	struct rule		*rule;
	enum cmp		 cmp;
}

%token <number> NUMBER SIZE
%token <string> STRING STRMACRO STRMACROB NUMMACRO NUMMACROB

%type  <accounts> accounts accountslist
%type  <action> action
%type  <actions> actions actionslist
%type  <area> area
%type  <cmp> cmp
%type  <domains> domains domainslist
%type  <expr> expr exprlist
%type  <expritem> expritem
%type  <exprop> exprop
%type  <fetch> fetchtype
%type  <flag> cont icase not disabled keep poptype imaptype execpipe
%type  <headers> headers headerslist
%type  <locks> lock locklist
%type  <match> match
%type  <number> size time numv retrc
%type  <rule> perform
%type  <server> server
%type  <string> port to folder strv retre
%type  <uid> uid user
%type  <users> users userslist

%%

/* Rules */

cmds: /* empty */
    | cmds account
    | cmds defaction
    | cmds defmacro
    | cmds include
    | cmds rule
    | cmds set
    | cmds close

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

	      $$ = xstrdup(macro->value.string);

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

	      $$ = xstrdup(macro->value.string);

	      xfree($1);
      }

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

	      $$ = macro->value.number;

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

	      $$ = macro->value.number;

	      xfree($1);
      }

include: TOKINCLUDE strv
	 {
		 char			*path;
		 struct filestackent	*top;

		 if (*$2 == '\0')
			 yyerror("invalid include file");

		 top = xmalloc(sizeof *top);
		 top->yyin = yyin;
		 top->yylineno = yylineno;
		 top->curfile = curfile;
		 ARRAY_ADD(&filestack, top, struct filestackent *);

		 yyin = fopen($2, "r");
		 if (yyin == NULL) {
			 xasprintf(&path, "%s/%s", dirname(conf.conf_file), $2);
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

size: numv
    | SIZE
      {
	      $$ = $1;
      }

time: numv TOKHOURS
      {
	      if ($1 > LLONG_MAX / TIME_HOUR)
		      yyerror("time is too long");
	      $$ = $1 * TIME_HOUR;
      }
    | numv TOKMINUTES
      {
	      if ($1 > LLONG_MAX / TIME_MINUTE)
		      yyerror("time is too long");
	      $$ = $1 * TIME_MINUTE;
      }
    | numv TOKSECONDS
      {
	      $$ = $1;
      }
    | numv TOKDAYS
      {
	      if ($1 > LLONG_MAX / TIME_DAY)
		      yyerror("time is too long");
	      $$ = $1 * TIME_DAY;
      }
    | numv TOKWEEKS
      {
	      if ($1 > LLONG_MAX / TIME_WEEK)
		      yyerror("time is too long");
	      $$ = $1 * TIME_WEEK;
      }
    | numv TOKMONTHS
      {
	      if ($1 > LLONG_MAX / TIME_MONTH)
		      yyerror("time is too long");
	      $$ = $1 * TIME_MONTH;
      }
    | numv TOKYEARS
      {
	      if ($1 > LLONG_MAX / TIME_YEAR)
		      yyerror("time is too long");
	      $$ = $1 * TIME_YEAR;
      }

set: TOKSET TOKMAXSIZE size
     {
	     if ($3 > MAXMAILSIZE)
		     yyerror("maximum size too large: %lld", $3);
	     conf.max_size = $3;
     }
   | TOKSET TOKLOCKTYPES locklist
     {
	     if ($3 & LOCK_FCNTL && $3 & LOCK_FLOCK)
		     yyerror("fcntl and flock locking cannot be used together");
	     conf.lock_types = $3;
     }
   | TOKSET TOKLOCKFILE strv
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
     {
	     conf.def_user = $3;
     }
   | TOKSET domains
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
	     conf.impl_act = IMPLICIT_KEEP;
     }
   | TOKSET TOKIMPLACT TOKDROP
     {
	     conf.impl_act = IMPLICIT_DROP;
     }

defmacro: STRMACRO '=' STRING
     	  {
		  struct macro	*macro;

		  if ((macro = find_macro($1)) == NULL) {
			  macro = xmalloc(sizeof *macro);
			  if (strlen($1) > MAXNAMESIZE)
				  yyerror("macro name too long: %s", $1);
			  strlcpy(macro->name, $1, sizeof macro->name);
			  TAILQ_INSERT_HEAD(&macros, macro, entry);
		  }
		  macro->type = MACRO_STRING;
		  macro->value.string = $3;
		  xfree($1);
	  }
        | NUMMACRO '=' NUMBER
	  {
	     struct macro	*macro;

	     if ((macro = find_macro($1)) == NULL) {
		     macro = xmalloc(sizeof *macro);
		     if (strlen($1) > MAXNAMESIZE)
			     yyerror("macro name too long: %s", $1);
		     strlcpy(macro->name, $1, sizeof macro->name);
		     TAILQ_INSERT_HEAD(&macros, macro, entry);
	     }
	     macro->type = MACRO_NUMBER;
	     macro->value.number = $3;
	     xfree($1);
	  }

domains: TOKDOMAIN strv
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
	 {
		 $$ = $3;
	 }

domainslist: domainslist strv
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

headers: TOKHEADER strv
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
	 {
		 $$ = $3;
	 }

headerslist: headerslist strv
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

lock: LCKFCNTL
      {
	      $$ |= LOCK_FCNTL;
      }
    | LCKFLOCK
      {
	      $$ |= LOCK_FLOCK;
      }
    | LCKDOTLOCK
      {
	      $$ |= LOCK_DOTLOCK;
      }

locklist: locklist lock
	  {
		  $$ = $1 | $2;
	  }
	| lock
	  {
		  $$ = $1;
	  }
	| TOKNONE
	  {
		  $$ = 0;
	  }

uid: strv
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

user: /* empty */
      {
	      $$ = 0;
      }
    | TOKUSER uid
      {
	      $$ = $2;
      }

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
       {
	       $$.users = xmalloc(sizeof *$$.users);
	       ARRAY_INIT($$.users);
	       ARRAY_ADD($$.users, $2, uid_t);
	       $$.find_uid = 0;
       }
     | TOKUSERS '{' userslist '}'
       {
	       $$ = $3;
	       $$.find_uid = 0;
       }

userslist: userslist uid
	   {
		   $$ = $1;
		   ARRAY_ADD($$.users, $2, uid_t);
	   }
	 | uid
	   {
		   $$.users = xmalloc(sizeof *$$.users);
		   ARRAY_INIT($$.users);
		   ARRAY_ADD($$.users, $1, uid_t);
	   }

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

not: TOKNOT
      {
	      $$ = 1;
      }
    | /* empty */
      {
	      $$ = 0;
      }

keep: TOKKEEP
      {
	      $$ = 1;
      }
    | /* empty */
      {
	      $$ = 0;
      }

disabled: TOKDISABLED
          {
		  $$ = 1;
          }
        | /* empty */
	  {
		  $$ = 0;
	  }

port: TOKPORT strv
      {
	      if (*$2 == '\0')
		      yyerror("invalid port");

	      $$ = $2;
      }
    | TOKPORT numv
      {
	      xasprintf(&$$, "%lld", $2);
      }

server: TOKSERVER strv port
	{
		if (*$2 == '\0')
			yyerror("invalid host");

		$$.host = $2;
		$$.port = $3;
	}
      | TOKSERVER strv
	{
		if (*$2 == '\0')
			yyerror("invalid host");

		$$.host = $2;
		$$.port = NULL;
	}

to: /* empty */
    {
	    $$ = NULL;
    }
  | TOKTO strv
    {
	    if (*$2 == '\0')
		    yyerror("invalid to");

	    $$ = $2;
    }

action: TOKPIPE strv
	{
		if (*$2 == '\0')
			yyerror("invalid command");

		$$.deliver = &deliver_pipe;

		$$.data = $2;
	}
      | TOKREWRITE strv
	{
		if (*$2 == '\0')
			yyerror("invalid command");

		$$.deliver = &deliver_rewrite;

		$$.data = $2;
	}
      | TOKWRITE strv
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_write;

		$$.data = $2;
	}
      | TOKAPPEND strv
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_append;

		$$.data = $2;
	}
      | TOKMAILDIR strv
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_maildir;

		$$.data = $2;
	}
      | TOKMBOX strv
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$.deliver = &deliver_mbox;

		$$.data = $2;
	}
      | TOKSMTP server to
	{
		struct smtp_data	*data;

		$$.deliver = &deliver_smtp;

		data = xcalloc(1, sizeof *data);
		$$.data = data;

		data->server.host = $2.host;
		data->server.port = $2.port != NULL ? $2.port : xstrdup("smtp");
		data->server.ai = NULL;
		data->to = $3;
	}
      | TOKDROP
        {
		$$.deliver = &deliver_drop;
	}

defaction: TOKACTION strv users action
	   {
		   struct action	*t;
		   char			*s;

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

		   s = t->deliver->desc(t);
		   log_debug2("added action: name=%s deliver=%s", t->name, s);
		   xfree(s);

		   xfree($2);
	   }

accounts: /* empty */
	  {
		  $$ = NULL;
	  }
        | TOKACCOUNT strv
	  {
		  if (*$2 == '\0')
			  yyerror("invalid account name");

		  $$ = xmalloc(sizeof *$$);
		  ARRAY_INIT($$);
		  if (find_account($2) == NULL)
			  yyerror("no matching accounts: %s", $2);
		  ARRAY_ADD($$, $2, char *);
	  }
	| TOKACCOUNTS '{' accountslist '}'
	  {
		  $$ = $3;
	  }

accountslist: accountslist strv
 	      {
		      if (*$2 == '\0')
			      yyerror("invalid account name");

		      $$ = $1;
		      if (find_account($2) == NULL)
			      yyerror("no matching accounts: %s", $2);
		      ARRAY_ADD($$, $2, char *);
	      }
	    | strv
	      {
		      if (*$1 == '\0')
			      yyerror("invalid account name");

		      $$ = xmalloc(sizeof *$$);
		      ARRAY_INIT($$);
		      if (find_account($1) == NULL)
			      yyerror("no matching accounts: %s", $1);
		      ARRAY_ADD($$, $1, char *);
	      }

actions: TOKACTION TOKNONE
	 {
		 $$ = NULL;
	 }
       | TOKACTION strv
	 {
		 struct actionptrs	*ta;

		 if (*$2 == '\0')
			 yyerror("invalid action name");
		 /* XXX check better? or not at all? */
		 if (strchr($2, '%') == NULL) {
			 ta = find_actions($2);
			 if (ARRAY_EMPTY(ta)) {
				 ARRAY_FREEALL(ta);
				 yyerror("unknown action: %s", $2);
			 }
			 ARRAY_FREEALL(ta);
		 }

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_ADD($$, $2, char *);
	 }
       | TOKACTIONS '{' actionslist '}'
         {
		 $$ = $3;
	 }

actionslist: actionslist strv
	     {
		     struct actionptrs	*ta;

		     if (*$2 == '\0')
			     yyerror("invalid action name");
 		     /* XXX check better? or not at all? */
		     if (strchr($2, '%') == NULL) {
			     ta = find_actions($2);
			     if (ARRAY_EMPTY(ta)) {
				     ARRAY_FREEALL(ta);
				     yyerror("unknown action: %s", $2);
			     }
			     ARRAY_FREEALL(ta);
		     }

		     $$ = $1;
		     ARRAY_ADD($$, $2, char *);
	     }
	   | strv
	     {
		     struct actionptrs	*ta;

		     if (*$1 == '\0')
			     yyerror("invalid action name");
 		     /* XXX check better? or not at all? */
		     if (strchr($1, '%') == NULL) {
			     ta = find_actions($1);
			     if (ARRAY_EMPTY(ta)) {
				     ARRAY_FREEALL(ta);
				     yyerror("unknown action: %s", $1);
			     }
			     ARRAY_FREEALL(ta);
		     }

		     $$ = xmalloc(sizeof *$$);
		     ARRAY_INIT($$);
		     ARRAY_ADD($$, $1, char *);
	     }

cont: /* empty */
      {
	      $$ = 0;
      }
    | TOKCONTINUE
      {
	      $$ = 1;
      }

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

retrc: numv
       {
	       if ($1 < 0 || $1 > 255)
		       yyerror("invalid return code");

	       $$ = $1;
       }
     | /* empty */
       {
	       $$ = -1;
       }

retre: strv
       {
	       if (*$1 == '\0')
		       yyerror("invalid regexp");

	       $$ = $1;
       }
     | /* empty */
       {
	       $$ = NULL;
       }

cmp: '<'
     {
	     $$ = CMP_LT;
     }
   | '>'
     {
	     $$ = CMP_GT;
     }
   | TOKEQ
     {
	     $$ = CMP_EQ;
     }
   | TOKNE
     {
	     $$ = CMP_NE;
     }

execpipe: TOKEXEC
	  {
		  $$ = 0;
	  }
        | TOKPIPE
	  {
		  $$ = 1;
	  }

exprop: TOKAND
	{
		$$ = OP_AND;
        }
      | TOKOR
	{
		$$ = OP_OR;
	}

expritem: not icase strv area
          {
		  struct regexp_data	*data;
		  int	 		 error, flags;
		  size_t	 	 len;
		  char			*buf;

		  if (*$3 == '\0')
			  yyerror("invalid regexp");

		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_regexp;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->re_s = $3;
		  data->area = $4;

		  flags = REG_EXTENDED|REG_NEWLINE;
		  if ($2)
			  flags |= REG_ICASE;
		  if ((error = regcomp(&data->re, $3, flags)) != 0) {
			  len = regerror(error, &data->re, NULL, 0);
			  buf = xmalloc(len);
			  regerror(error, &data->re, buf, len);
			  yyerror("%s: %s", $3, buf);
		  }
	  }
        | not execpipe strv user TOKRETURNS '(' retrc ',' retre ')'
	  {
		  struct command_data	*data;
		  int	 		 error, flags;
		  size_t	 	 len;
		  char			*buf;

		  if (*$3 == '\0' || ($3[0] == '|' && $3[1] == '\0'))
			  yyerror("invalid command");
		  if ($7 == -1 && $9 == NULL)
			  yyerror("return code or regexp must be specified");
		  if ($9 != NULL && *$9 == '\0')
			  yyerror("invalid regexp");

		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_command;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->uid = $4;
		  data->pipe = $2;
		  data->cmd = $3;

		  data->ret = $7;
		  data->re_s = $9;

		  if ($9 != NULL) {
			  flags = REG_EXTENDED|REG_NOSUB|REG_NEWLINE;
			  if ((error = regcomp(&data->re, $9, flags)) != 0) {
				  len = regerror(error, &data->re, NULL, 0);
				  buf = xmalloc(len);
				  regerror(error, &data->re, buf, len);
				  yyerror("%s: %s", $9, buf);
			  }
		  }

	  }
	| not TOKTAGGED strv
	  {
		  struct tagged_data	*data;

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
	  {
		  struct size_data	*data;

		  if ($4 > SIZE_MAX)
			  yyerror("size too large");
		  if ($3 == CMP_EQ || $3 == CMP_NE)
			  yyerror("can't compare size with == or !=");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_size;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->size = $4;
		  data->cmp = $3;
	  }
        | not TOKSTRING strv TOKTO strv
	  {
		  struct string_data	*data;
		  int	 		 error, flags;
		  size_t	 	 len;
		  char			*buf;

		  if (*$3 == '\0')
			  yyerror("invalid string");
		  if (*$5 == '\0')
			  yyerror("invalid regexp");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_string;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->re_s = $5;
		  data->s = $3;

		  flags = REG_EXTENDED|REG_NOSUB|REG_NEWLINE;
		  if ((error = regcomp(&data->re, $5, flags)) != 0) {
			  len = regerror(error, &data->re, NULL, 0);
			  buf = xmalloc(len);
			  regerror(error, &data->re, buf, len);
			  yyerror("%s: %s", $5, buf);
		  }
	  }
        | not TOKMATCHED
	  {
		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_matched;
		  $$->inverted = $1;
          }
        | not TOKUNMATCHED
	  {
		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_unmatched;
		  $$->inverted = $1;
          }
        | not TOKAGE cmp time
	  {
		  struct age_data	*data;

		  if ($4 == 0)
			  yyerror("invalid time");
		  if ($3 == CMP_EQ || $3 == CMP_NE)
			  yyerror("can't compare age with == or !=");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_age;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->time = $4;
		  data->cmp = $3;
	  }
        | not TOKAGE TOKINVALID
	  {
		  struct age_data	*data;

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_age;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->time = -1;
	  }

exprlist: exprlist exprop expritem
	  {
		  $$ = $1;

		  $3->op = $2;
		  TAILQ_INSERT_TAIL($$, $3, entry);
	  }
        | exprop expritem
	  {
		  $$ = xmalloc(sizeof *$$);
		  TAILQ_INIT($$);

		  $2->op = $1;
		  TAILQ_INSERT_HEAD($$, $2, entry);
	  }

expr: expritem
      {
	      $$ = xmalloc(sizeof *$$);
	      TAILQ_INIT($$);

	      TAILQ_INSERT_HEAD($$, $1, entry);
      }
    | expritem exprlist
      {
	      $$ = $2;

	      TAILQ_INSERT_HEAD($$, $1, entry);
      }

match: TOKMATCH expr
       {
	       $$.expr = $2;
	       $$.type = RULE_EXPRESSION;
       }
     | TOKMATCH TOKALL
       {
	       $$.expr = NULL;
	       $$.type = RULE_ALL;
       }

perform: TOKTAG strv
	 {
		 if (*$2 == '\0')
			 yyerror("invalid tag");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->actions = NULL;
		 $$->tag = $2;
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
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->actions = $2;
		 $$->tag = NULL;
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
		 $$->actions = NULL;
		 $$->tag = NULL;
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

close: '}'
       {
	       if (currule == NULL)
		       yyerror("missing {");

	       currule = ARRAY_LAST(&rulestack, struct rule *);
	       ARRAY_TRUNC(&rulestack, 1, struct rule *);
       }

rule: match accounts perform
      {
	      struct expritem	*ei;
	      char		 tmp[1024], tmp2[1024], *s;
	      u_int		 i;

	      $3->accounts = $2;
	      $3->expr = $1.expr;
	      $3->type = $1.type;

	      switch ($3->type) {
 	      case RULE_ALL:
		      xsnprintf(tmp, sizeof tmp, "all");
		      break;
	      case RULE_EXPRESSION:
		      *tmp = '\0';
		      TAILQ_FOREACH(ei, $3->expr, entry) {
			      s = ei->match->desc(ei);
			      switch (ei->op) {
			      case OP_AND:
				      xsnprintf(tmp2, sizeof tmp2,
					  "and %s:%s ", ei->match->name, s);
				      break;
			      case OP_OR:
				      xsnprintf(tmp2, sizeof tmp2,
					  "or %s:%s ", ei->match->name, s);
				      break;
			      case OP_NONE:
				      xsnprintf(tmp2, sizeof tmp2,
					  "%s:%s ", ei->match->name, s);
				      break;
			      }
			      xfree(s);
			      if (ei->inverted)
				      strlcat(tmp, "not ", sizeof tmp);
			      strlcat(tmp, tmp2, sizeof tmp);
		      }
		      break;
	      }
	      if ($3->actions != NULL) {
		      *tmp2 = '\0';
		      for (i = 0; i < ARRAY_LENGTH($3->actions); i++) {
			      strlcat(tmp2, ARRAY_ITEM($3->actions, i, char *),
				  sizeof tmp2);
			      strlcat(tmp2, " ", sizeof tmp2);
		      }
		      log_debug2("added rule: actions=%smatches=%s", tmp2, tmp);
	      } else if ($3->tag != NULL)
		      log_debug2("added rule: tag=%s matches=%s", $3->tag, tmp);
	      else
		      log_debug2("added rule: nested matches=%s", tmp);
      }

folder: /* empty */
        {
		$$ = NULL;
        }
      | TOKFOLDER strv
	{
		if (*$2 == '\0')
			yyerror("invalid folder");

		$$ = $2;
	}

poptype: TOKPOP3
         {
		 $$ = 0;
         }
       | TOKPOP3S
	 {
		 $$ = 1;
	 }

imaptype: TOKIMAP
          {
		  $$ = 0;
          }
        | TOKIMAPS
	  {
		  $$ = 1;
	  }

fetchtype: poptype server TOKUSER strv TOKPASS strv
           {
		   struct pop3_data	*data;

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
           {
		   struct imap_data	*data;

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
	 | TOKSTDIN
	   {
		   struct stdin_data	*data;

		   $$.fetch = &fetch_stdin;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
	   }

account: TOKACCOUNT strv disabled fetchtype keep
         {
		 struct account		*a;
		 char			*s;

		 if (strlen($2) >= MAXNAMESIZE)
			 yyerror("account name too long: %s", $2);
		 if (*$2 == '\0')
			 yyerror("invalid account name");
		 if (find_account($2) != NULL)
			 yyerror("duplicate account: %s", $2);

		 a = xcalloc(1, sizeof *a);
		 strlcpy(a->name, $2, sizeof a->name);
		 a->keep = $5;
		 a->disabled = $3;
		 a->fetch = $4.fetch;
		 a->data = $4.data;
		 TAILQ_INSERT_TAIL(&conf.accounts, a, entry);

		 s = a->fetch->desc(a);
		 log_debug2("added account: name=%s fetch=%s", a->name, s);
		 xfree(s);
	 }

%%

/* Programs */
