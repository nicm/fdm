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
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "fdm.h"

int			 rules;

extern int		 yylineno;
extern int 		 yylex(void);

int			 yyparse(void);
__dead printflike1 void  yyerror(const char *, ...);
int 			 yywrap(void);

struct account 		*find_account(char *);
struct action  		*find_action(char *);

__dead printflike1 void
yyerror(const char *fmt, ...)
{
	va_list	 ap;
	char	*s;

	xasprintf(&s, "%s: %s at line %d", conf.conf_file, fmt, yylineno);

	va_start(ap, fmt);
	vlog(LOG_CRIT, s, ap);
	va_end(ap);

	exit(1);
}

int
yywrap(void)
{
        return (1);
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
%}

%token SYMOPEN SYMCLOSE
%token TOKALL TOKACCOUNT TOKSERVER TOKPORT TOKUSER TOKPASS TOKACTION TOKCOMMAND
%token TOKSET TOKACCOUNTS TOKMATCH TOKIN TOKCONTINUE TOKSTDIN TOKPOP3 TOKPOP3S
%token TOKNONE TOKCASE TOKAND TOKOR TOKTO TOKACTIONS TOKHEADERS TOKBODY
%token TOKMAXSIZE TOKDELTOOBIG TOKLOCKTYPES TOKDEFUSER TOKDOMAIN TOKDOMAINS
%token TOKHEADER TOKFROMHEADERS TOKUSERS
%token ACTPIPE ACTSMTP ACTDROP ACTMAILDIR ACTMBOX ACTWRITE ACTAPPEND
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
	enum area	 	 area;
	enum op			 op;
	struct accounts		*accounts;
	struct action	 	 action;
	struct actions		*actions;
	struct domains		*domains;
	struct headers	 	*headers;
	struct match		*match;
	struct matches		*matches;
	uid_t			 uid;
	struct {
		struct users	*users;
		int		 find_uid;
	} users;
}

%token <number> NUMBER
%token <number> SIZE
%token <string> STRING

%type  <accounts> accounts accountslist
%type  <action> action
%type  <actions> actions actionslist
%type  <area> area
%type  <domains> domains domainslist
%type  <fetch> poptype fetchtype
%type  <flag> cont icase
%type  <headers> headers headerslist
%type  <locks> lock locklist
%type  <match> match
%type  <matches> matches matchlist
%type  <number> size
%type  <op> op
%type  <server> server
%type  <string> port command to
%type  <uid> uid
%type  <users> users userslist

%%

/* Rules */

cmds: /* empty */
    | cmds set
    | cmds account
    | cmds define
    | cmds rule

size: NUMBER
    | SIZE
      {
	      $$ = $1;
      }

set: TOKSET TOKMAXSIZE size
     {
	     if ($3 > MAXMAILSIZE)
		     yyerror("maxsize too large: %lld", $3);
	     conf.max_size = $3;
     }
   | TOKSET TOKLOCKTYPES locklist
     {
	     if ($3 & LOCK_FCNTL && $3 & LOCK_FLOCK)
		     yyerror("fcntl and flock locking cannot be used together");
	     conf.lock_types = $3;
     }
   | TOKSET TOKDELTOOBIG
     {
	     conf.del_big = 1;
     }
   | TOKSET TOKDEFUSER uid
     {
	     if (conf.def_user == 0)
		     conf.def_user = $3;
     }
   | TOKSET domains
     {
	     if (conf.domains != NULL)
		     yyerror("cannot set domains twice");
	     conf.domains = $2;
     }
   | TOKSET headers
     {
	     if (conf.headers != NULL)
		     yyerror("cannot set headers twice");
	     conf.headers = $2;
     }

domains: TOKDOMAIN STRING
	 {
		 char	*cp;

		 $$ = xmalloc(sizeof (struct domains));
		 ARRAY_INIT($$);
		 for (cp = $2; *cp != '\0'; cp++)
			 *cp = tolower((int) *cp);
		 ARRAY_ADD($$, $2, char *);
	 }
       | TOKDOMAINS SYMOPEN domainslist SYMCLOSE
	 {
		 $$ = $3;
	 }

domainslist: domainslist STRING
	     {
		     char	*cp;

		     $$ = $1;
		     for (cp = $2; *cp != '\0'; cp++)
			     *cp = tolower((int) *cp);
		     ARRAY_ADD($$, $2, char *);
	     }	
	   | STRING
	     {
		     char	*cp;

		     $$ = xmalloc(sizeof (struct domains));
		     ARRAY_INIT($$);
		     for (cp = $1; *cp != '\0'; cp++)
			     *cp = tolower((int) *cp);
		     ARRAY_ADD($$, $1, char *);
	     }

headers: TOKHEADER STRING
	 {
		 char	*cp;

		 $$ = xmalloc(sizeof (struct headers));
		 ARRAY_INIT($$);
		 for (cp = $2; *cp != '\0'; cp++)
			 *cp = tolower((int) *cp);
		 ARRAY_ADD($$, $2, char *);
	 }
       | TOKHEADERS SYMOPEN headerslist SYMCLOSE
	 {
		 $$ = $3;
	 }

headerslist: headerslist STRING
	     {
		     char	*cp;
		 
		     $$ = $1;
		     for (cp = $2; *cp != '\0'; cp++)
			     *cp = tolower((int) *cp);
		     ARRAY_ADD($$, $2, char *);
	     }	
	   | STRING
	     {
		     char	*cp;

		     $$ = xmalloc(sizeof (struct headers));
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

uid: STRING
     {
	     struct passwd	*pw;
	     
	     pw = getpwnam($1);
	     if (pw == NULL)
		     yyerror("unknown user: %s", $1);
	     if (pw->pw_uid == 0)
		     yyerror("cannot change to uid 0 user");
	     $$ = pw->pw_uid;
	     endpwent();
     }
   | NUMBER
     {
	     struct passwd	*pw;
	     
	     if ($1 > UID_MAX)
		     yyerror("invalid uid: %llu", $1); 
	     pw = getpwuid($1);
	     if (pw == NULL)
		     yyerror("unknown uid: %llu", $1);
	     if (pw->pw_uid == 0)
		     yyerror("cannot change to uid 0 user");
	     $$ = pw->pw_uid;
	     endpwent();
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
     | TOKUSER uid
       {
	       $$.users = xmalloc(sizeof (struct users));
	       ARRAY_INIT($$.users);
	       ARRAY_ADD($$.users, $2, uid_t);
	       $$.find_uid = 0;
       }
     | TOKUSERS SYMOPEN userslist SYMCLOSE
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
		   $$.users = xmalloc(sizeof (struct users));
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

port: TOKPORT STRING
      {
	      $$ = $2;
      }	
    | TOKPORT NUMBER
      {
	      xasprintf(&$$, "%lld", $2);
      }

server: TOKSERVER STRING port
	{
		$$.host = $2;
		$$.port = $3;
	}
      | TOKSERVER STRING
	{
		$$.host = $2;
		$$.port = NULL;
	}

command: TOKCOMMAND STRING
	 {
		 $$ = $2;
	 }
       | STRING
	 {
		 $$ = $1;
	 }

to: /* empty */
    {
	    $$ = NULL;
    } 
  | TOKTO STRING
    {
	    $$ = $2;
    }

action: ACTPIPE command
	{
		$$.deliver = &deliver_pipe;
		$$.data = $2;
	}
      | ACTWRITE command
	{
		$$.deliver = &deliver_write;
		$$.data = $2;
	}
      | ACTAPPEND command
	{
		$$.deliver = &deliver_append;
		$$.data = $2;
	}
      | ACTMAILDIR STRING
	{
		$$.deliver = &deliver_maildir;
		$$.data = $2;
	}
      | ACTMBOX STRING
	{
		$$.deliver = &deliver_mbox;
		$$.data = $2;
	}
      | ACTSMTP server to
	{
		struct smtp_data	*data;
		int		 	 error;
		struct addrinfo		 hints;

		$$.deliver = &deliver_smtp;
		
		data = xcalloc(1, sizeof *data);
		$$.data = data;

		data->to = $3;

		memset(&hints, 0, sizeof hints);
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		error = getaddrinfo($2.host, $2.port != NULL ? $2.port : 
		    "smtp", &hints, &data->ai);
		if (error != 0)
			yyerror("%s", gai_strerror(error));

		xfree($2.host);
		if ($2.port != NULL)
			xfree($2.port);
	}
      | ACTDROP
        {
		$$.deliver = &deliver_drop;
	}

define: TOKACTION STRING users action
	{
		struct action	*t;

		if (strlen($2) >= MAXNAMESIZE)
			yyerror("name too long: %s", $2);
		if (*$2 == '\0')
			yyerror("empty name");
		if (find_action($2) != NULL)
			yyerror("duplicate action: %s", $2);
		
		t = xmalloc(sizeof *t);
		memcpy(t, &$4, sizeof *t);
		strlcpy(t->name, $2, sizeof t->name);
		t->users = $3.users;
		t->find_uid = $3.find_uid;
		TAILQ_INSERT_TAIL(&conf.actions, t, entry);

		log_debug2("added action: name=%s deliver=%s", t->name,
		    t->deliver->name);

		xfree($2);
	}

accounts: /* empty */
	  {
		  $$ = NULL;
	  }
        | TOKACCOUNT STRING
	  {
		  $$ = xmalloc(sizeof (struct accounts));
		  ARRAY_INIT($$);
		  if (find_account($2) == NULL)
			  yyerror("unknown account: %s", $2);
		  ARRAY_ADD($$, $2, char *);
	  }
	| TOKACCOUNTS SYMOPEN accountslist SYMCLOSE
	  {
		  $$ = $3;
	  }	

accountslist: accountslist STRING
 	      {
		      $$ = $1;
		      if (find_account($2) == NULL)
			      yyerror("unknown account: %s", $2);
		      ARRAY_ADD($$, $2, char *);
	      }	
	    | STRING
	      {
		      $$ = xmalloc(sizeof (struct accounts));
		      ARRAY_INIT($$);
		      if (find_account($1) == NULL)
			      yyerror("unknown account: %s", $1);
		      ARRAY_ADD($$, $1, char *);
	      }

actions: TOKACTION STRING
	 {
		 struct action	*t;
		 
		 $$ = xmalloc(sizeof (struct actions));
		 ARRAY_INIT($$);
		 if ((t = find_action($2)) == NULL)
			 yyerror("unknown action: %s", $2);
		 ARRAY_ADD($$, t, struct action *);
		 free($2);
	 }
       | TOKACTIONS SYMOPEN actionslist SYMCLOSE
         {
		 $$ = $3;
	 }

actionslist: actionslist STRING
	     {
		     struct action	*t;

		     $$ = $1;
		     if ((t = find_action($2)) == NULL)
			     yyerror("unknown action: %s", $2);
		     ARRAY_ADD($$, t, struct action *);
		     free($2);
	     }	
	   | STRING
	     {
		     struct action	*t;
		     
		     $$ = xmalloc(sizeof (struct actions));
		     ARRAY_INIT($$);
		     if ((t = find_action($1)) == NULL)
			     yyerror("unknown action: %s", $1);
		     ARRAY_ADD($$, t, struct action *);
		     free($1);
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

op: TOKAND
    {
	    $$ = OP_AND;
    }
  | TOKOR
    {
	    $$ = OP_OR;
    }

match: icase STRING area
       {
	       int	 error, flags;
	       size_t	 len;
	       char	*buf;

	       $$ = xcalloc(1, sizeof (struct match));
	       $$->s = $2;
	       $$->op = OP_NONE;
	       $$->area = $3;

	       flags = REG_EXTENDED|REG_NOSUB|REG_NEWLINE;
	       if ($1)
		       flags |= REG_ICASE;
	       if ((error = regcomp(&$$->re, $2, flags)) != 0) {
		       len = regerror(error, &$$->re, NULL, 0);
		       buf = xmalloc(len);
		       regerror(error, &$$->re, buf, len);
		       yyerror("%s", buf);
	       }
       }

matchlist: matchlist op match
	   {
		   $$ = $1;
		   $3->op = $2;
		   TAILQ_INSERT_TAIL($$, $3, entry);
	   }
         | op match
	   {
		   $$ = xcalloc(1, sizeof (struct matches));
		   $2->op = $1;
		   TAILQ_INSERT_HEAD($$, $2, entry);
	   }

matches: TOKMATCH match matchlist
         {
		 if ($3 != NULL)
			 $$ = $3;
		 else
			 $$ = xcalloc(1, sizeof (struct matches));
		 TAILQ_INSERT_HEAD($$, $2, entry);
	 }
       | TOKMATCH match
         {
		 $$ = xcalloc(1, sizeof (struct matches));
		 TAILQ_INSERT_HEAD($$, $2, entry);
	 }
       | TOKMATCH TOKALL
	 {
		 $$ = NULL;
	 }

rule: matches accounts users actions cont
      {
	      struct rule	*r;
	      struct match	*c;
	      char		 tmp[1024], tmp2[1024];
	      u_int		 i;

	      r = xcalloc(1, sizeof *r);      
	      r->index = rules++;
	      r->stop = !$5;
	      r->accounts = $2;
	      r->matches = $1;
	      r->users = $3.users;
	      r->find_uid = $3.find_uid;
	      r->actions = $4;
	      
	      TAILQ_INSERT_TAIL(&conf.rules, r, entry);

	      if (r->matches == NULL)
		      xsnprintf(tmp, sizeof tmp, "all");
	      else {
		      *tmp = '\0';
		      TAILQ_FOREACH(c, r->matches, entry) {
			      switch (c->op) {
			      case OP_AND:
				      strlcat(tmp, "and \"", sizeof tmp);
				      break;
			      case OP_OR:
				      strlcat(tmp, "or \"", sizeof tmp);
				      break;
			      case OP_NONE:
				      strlcat(tmp, "\"", sizeof tmp);
				      break;
			      }
			      strlcat(tmp, c->s, sizeof tmp);
			      strlcat(tmp, "\" ", sizeof tmp);
			      switch (c->area) {
			      case AREA_BODY:
				      strlcat(tmp, "in body ", sizeof tmp);
				      break;
			      case AREA_HEADERS:
				      strlcat(tmp, "in headers ", sizeof tmp);
				      break;
			      case AREA_ANY:
				      strlcat(tmp, "in any ", sizeof tmp);
				      break;
			      }
		      }
	      }
	      *tmp2 = '\0';
	      for (i = 0; i < ARRAY_LENGTH($4); i++) {
		      strlcat(tmp2, ARRAY_ITEM($4, i, struct action *)->name,
			  sizeof tmp2);
		      strlcat(tmp2, " ", sizeof tmp2);
	      }
			  
	      log_debug2("added rule: index=%u actions=%smatches=%s", r->index,
		  tmp2, tmp);
      }

poptype: TOKPOP3
         {
		 $$.fetch = &fetch_pop3;
         }
       | TOKPOP3S
	 {	
		 $$.fetch = &fetch_pop3s;
	 }

fetchtype: poptype server TOKUSER STRING TOKPASS STRING
           {
		   struct pop3_data	*data;
		   int		 	 error;
		   struct addrinfo	 hints;
		   
		   $$ = $1;
		   
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->user = $4;
		   data->pass = $6;
		   
		   memset(&hints, 0, sizeof hints);
		   hints.ai_family = PF_UNSPEC;
		   hints.ai_socktype = SOCK_STREAM;
		   error = getaddrinfo($2.host, $2.port != NULL ? $2.port :
		       $1.fetch->port, &hints, &data->ai);
		   if (error != 0)
			   yyerror("%s", gai_strerror(error));
		   
		   xfree($2.host);
		   if ($2.port != NULL)
			   xfree($2.port);
	   }
	 | TOKSTDIN
	   {
		   $$.fetch = &fetch_stdin;
		   $$.data = xmalloc(sizeof (struct stdin_data));
	   }

account: TOKACCOUNT STRING fetchtype
         {
		 struct account		*a;

		 if (strlen($2) >= MAXNAMESIZE)
			 yyerror("name too long: %s", $2);
		 if (*$2 == '\0')
			 yyerror("empty name");
		 if (find_account($2) != NULL)
			 yyerror("duplicate account: %s", $2);
		 
		 a = xcalloc(1, sizeof *a);
		 strlcpy(a->name, $2, sizeof a->name);
		 a->fetch = $3.fetch;
		 a->data = $3.data;
		 TAILQ_INSERT_TAIL(&conf.accounts, a, entry);

		 log_debug2("added account: name=%s fetch=%s", a->name,
		     a->fetch->name);
	 }

%%

/* Programs */
