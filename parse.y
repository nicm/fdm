/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "fdm.h"

extern int	yylineno;
extern int 	yylex(void);

int		yyparse(void);
void 		yyerror(const char *, ...);
int 		yywrap(void);

void		check_account(char *);

__dead void
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

void
check_account(char *name)
{
	struct account	*a;

	TAILQ_FOREACH(a, &conf.accounts, entry) {
		if (strcmp(a->name, name) == 0)
			break;
	}
	if (a == TAILQ_END(&conf.accounts))
		yyerror("unknown account \"%s\"", name);
}
%}

%token SYMOPEN SYMCLOSE SYMSTAR
%token TOKALL TOKACCOUNT TOKSERVER TOKPORT TOKUSER TOKPASS TOKACTION TOKCOMMAND
%token TOKSET TOKACCOUNTS TOKMATCH TOKIN TOKCONTINUE TOKSTDIN TOKPOP3 TOKPOP3S
%token TOKNONE TOKCASE TOKAND TOKOR
%token ACTPIPE ACTSMTP ACTDROP ACTMAILDIR ACTMBOX ACTWRITE ACTAPPEND
%token OPTMAXSIZE OPTDELOVERSIZED OPTLOCKTYPES
%token LCKFLOCK LCKFCNTL LCKDOTLOCK

%union
{
        int 	 	 	 number;
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
	struct action	 	 action;
	enum area	 	 area;
	enum op			 op;
	struct accounts		*accounts;
	struct matches		*matches;
	struct match		*match;
}

%token <number> NUMBER
%token <number> SIZE
%token <string> STRING
%token <area>	AREA

%type  <server> server
%type  <action> action
%type  <string> port command
%type  <accounts> accounts accountslist
%type  <flag> continue icase
%type  <number> size
%type  <fetch> poptype fetchtype
%type  <locks> lock locklist
%type  <area> area
%type  <match> match
%type  <matches> matches matchlist
%type  <op> op

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

set: TOKSET OPTMAXSIZE size
     {
	     if ($3 > MAXMAILSIZE)
		     yyerror("maxsize too large: %d", $3);
	     conf.max_size = $3;
     }
   | TOKSET OPTLOCKTYPES locklist
     {
	     if ($3 & LOCK_FCNTL && $3 & LOCK_FLOCK)
		     yyerror("fcntl and flock locking cannot be used together");
	     conf.lock_types = $3;
     }
   | TOKSET OPTDELOVERSIZED
     {
	     conf.del_oversized = 1;
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
	      xasprintf(&$$, "%d", $2);
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
      | ACTSMTP server
	{
		int		 error;
		struct addrinfo	 hints;

		$$.deliver = &deliver_smtp;

		memset(&hints, 0, sizeof hints);
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		error = getaddrinfo($2.host, $2.port != NULL ? $2.port : 
		    "smtp", &hints, (struct addrinfo **) &$$.data);
		if (error != 0)
			yyerror(gai_strerror(error));

		xfree($2.host);
		if ($2.port != NULL)
			xfree($2.port);
	}
      | ACTDROP
        {
		$$.deliver = &deliver_drop;
	}

define: TOKACTION STRING action
	{
		struct action	*t, *u;

		TAILQ_FOREACH(u, &conf.actions, entry) {
			if (strcmp(u->name, $2) == 0)
				yyerror("duplicate action \"%s\"", $2);
		}

		t = xmalloc(sizeof *t);
		memcpy(t, &$3, sizeof *t);
		t->name = $2;
		TAILQ_INSERT_TAIL(&conf.actions, t, entry);

		log_debug("added action: name=%s deliver=%s", t->name,
		    t->deliver->name);
	}

all: SYMSTAR
   | TOKALL

accounts: /* empty */
	  {
		  $$ = NULL;
	  }
	| TOKACCOUNTS all
	  {
		  $$ = NULL;
	  }
	| TOKACCOUNT all
	  {
		  $$ = NULL;
	  }
	| TOKACCOUNTS STRING
	  {
		  $$ = xmalloc(sizeof (struct accounts));
		  ACCOUNTS_INIT($$);
		  check_account($2);
		  ACCOUNTS_ADD($$, $2);
	  }
        | TOKACCOUNT STRING
	  {
		  $$ = xmalloc(sizeof (struct accounts));
		  ACCOUNTS_INIT($$);
		  check_account($2);
		  ACCOUNTS_ADD($$, $2);
	  }
	| TOKACCOUNTS SYMOPEN accountslist SYMCLOSE
	  {
		  $$ = $3;
	  }	

accountslist: accountslist STRING
 	      {
		      $$ = $1;
		      check_account($2);
		      ACCOUNTS_ADD($$, $2);
	      }	
	    | STRING
	      {
		      $$ = xmalloc(sizeof (struct accounts));
		      ACCOUNTS_INIT($$);
		      check_account($1);
		      ACCOUNTS_ADD($$, $1);
	      }

continue: /* empty */
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
    | TOKIN AREA
      {
	      $$ = $2;
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
       | TOKMATCH all
	 {
		 $$ = NULL;
	 }

rule: matches accounts TOKACTION STRING continue
      {
	      struct rule	*r;
	      struct action	*t;
	      char		 tmp[1024];
	      struct match	*c;

	      r = xcalloc(1, sizeof *r);      
	      r->stop = !$5;
	      r->accounts = $2;
	      r->matches = $1;

	      r->action = NULL;
	      TAILQ_FOREACH(t, &conf.actions, entry) {
		      if (strcmp(t->name, $4) == 0)
			      r->action = t;
	      }
	      if (r->action == NULL)
		      yyerror("unknown action \"%s\"", $4);
	      
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
	      
	      log_debug("added rule: action=%s matches=%s", $4, tmp);
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
		   
		   $$ = $1; /* XXX is this okay? */
		   
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
			   yyerror(gai_strerror(error));
		   
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
		 
		 a = xcalloc(1, sizeof *a);
		 a->name = $2;
		 a->fetch = $3.fetch;
		 a->data = $3.data;
		 TAILQ_INSERT_TAIL(&conf.accounts, a, entry);

		 log_debug("added account: name=%s fetch=%s", a->name,
		     a->fetch->name);
	 }

%%

/* Programs */
