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
#include <sys/stat.h>

#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <syslog.h>

#include "fdm.h"
#include "deliver.h"
#include "fetch.h"
#include "match.h"

struct strb	*parse_tags;
struct macros	 parse_macros;
struct macro	*parse_last;	/* last command-line argument macro */

u_int		 parse_ruleidx;
u_int		 parse_actionidx;

ARRAY_DECL(, struct rule *) parse_rulestack;
struct rule	*parse_rule;

struct files	 parse_filestack;
struct file	*parse_file;

int		 yyparse(void);

int
parse_conf(const char *path, struct strings *macros)
{
	struct macro	*macro;
	FILE		*f;
	u_int		 i;

        if ((f = fopen(path, "r")) == NULL)
                return (-1);

	ARRAY_INIT(&parse_rulestack);
	parse_rule = NULL;

	ARRAY_INIT(&parse_filestack);
	parse_file = xmalloc(sizeof *parse_file);

	parse_file->f = f;
	parse_file->line = 0;
	parse_file->path = path;

	strb_create(&parse_tags);
	default_tags(&parse_tags, NULL);

	TAILQ_INIT(&parse_macros);
	parse_last = NULL;
	for (i = 0; i < ARRAY_LENGTH(macros); i++) {
		parse_last = extract_macro(ARRAY_ITEM(macros, i));
		TAILQ_INSERT_TAIL(&parse_macros, parse_last, entry);
	}

	parse_file->line++;
        yyparse();

	if (!ARRAY_EMPTY(&parse_rulestack))
		yyerror("missing }");
	ARRAY_FREE(&parse_rulestack);

	ARRAY_FREE(&parse_filestack);
	xfree(parse_file);

	while (!TAILQ_EMPTY(&parse_macros)) {
		macro = TAILQ_FIRST(&parse_macros);
		TAILQ_REMOVE(&parse_macros, macro, entry);

		if (macro->type == MACRO_STRING)
			xfree(macro->value.str);
		xfree(macro);
	}

	strb_destroy(&parse_tags);

        fclose(f);
        return (0);
}

__dead printflike1 void
yyerror(const char *fmt, ...)
{
	va_list	ap;
	char   *s;

	xasprintf(&s,
	    "%s: %s at line %d", parse_file->path, fmt, parse_file->line);

	va_start(ap, fmt);
	log_vwrite(NULL, LOG_CRIT, s, ap);
	va_end(ap);

	exit(1);
}
%}

%token TOKALL TOKACCOUNT TOKSERVER TOKPORT TOKUSER TOKPASS TOKACTION
%token TOKSET TOKACCOUNTS TOKMATCH TOKIN TOKCONTINUE TOKSTDIN TOKPOP3 TOKPOP3S
%token TOKNONE TOKCASE TOKAND TOKOR TOKTO TOKACTIONS TOKHEADERS TOKBODY
%token TOKMAXSIZE TOKDELTOOBIG TOKLOCKTYPES TOKDEFUSER TOKDOMAIN TOKDOMAINS
%token TOKHEADER TOKFROMHEADERS TOKUSERS TOKMATCHED TOKUNMATCHED TOKNOT
%token TOKIMAP TOKIMAPS TOKDISABLED TOKFOLDER TOKPROXY TOKALLOWMANY TOKDROP
%token TOKLOCKFILE TOKRETURNS TOKPIPE TOKSMTP TOKMAILDIR TOKMBOX TOKMBOXES
%token TOKWRITE TOKAPPEND TOKREWRITE TOKTAG TOKTAGGED TOKSIZE TOKMAILDIRS
%token TOKEXEC TOKSTRING TOKKEEP TOKIMPLACT TOKHOURS TOKMINUTES TOKSECONDS
%token TOKDAYS TOKWEEKS TOKMONTHS TOKYEARS TOKAGE TOKINVALID TOKKILOBYTES
%token TOKMEGABYTES TOKGIGABYTES TOKBYTES TOKATTACHMENT TOKCOUNT TOKTOTALSIZE
%token TOKANYTYPE TOKANYNAME TOKANYSIZE TOKEQ TOKNE TOKNNTP TOKNNTPS
%token TOKGROUP TOKGROUPS TOKPURGEAFTER TOKCOMPRESS TOKNORECEIVED TOKFILEUMASK
%token TOKFILEGROUP TOKVALUE TOKTIMEOUT TOKREMOVEHEADER TOKREMOVEHEADERS
%token TOKSTDOUT TOKNOVERIFY TOKADDHEADER TOKQUEUEHIGH TOKQUEUELOW TOKNOAPOP
%token TOKVERIFYCERTS TOKEXPIRE TOKADDTOCACHE TOKREMOVEFROMCACHE TOKINCACHE
%token TOKKEY TOKNEWONLY TOKOLDONLY TOKCACHE TOKFLOCK TOKFCNTL TOKDOTLOCK
%token TOKSTRIPCHARACTERS TOKCMDUSER

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
	enum exprop		 exprop;
	struct actitem 		*actitem;
	struct actlist 		*actlist;
	struct expr		*expr;
	struct expritem		*expritem;
	struct strings		*strings;
	struct replstrs		*replstrs;
	enum fetch_only		 only;
	struct {
		char		*path;
		enum fetch_only	 only;
	} poponly;
	struct {
		int		 flags;
		char		*str;
	} re;
	uid_t			 uid;
	gid_t			 gid;
	struct {
		struct users	*users;
		int		 find_uid;
	} users;
	enum cmp		 cmp;
	struct rule		*rule;
	struct {
		char		*user;
		int		 user_netrc;
		char		*pass;
		int		 pass_netrc;
	} userpass;
}

%token NONE
%token <number> NUMBER
%token <string> STRING STRMACRO NUMMACRO
%token <string> STRCOMMAND NUMCOMMAND

%type  <actitem> actitem
%type  <actlist> actlist
%type  <area> area
%type  <cmp> cmp ltgt eqne
%type  <expr> expr exprlist
%type  <expritem> expritem
%type  <exprop> exprop
%type  <fetch> fetchtype
%type  <flag> cont not disabled keep execpipe writeappend compress verify
%type  <flag> apop poptype imaptype nntptype
%type  <gid> gid
%type  <locks> lock locklist
%type  <number> size time numv retrc expire
%type  <only> only imaponly
%type  <poponly> poponly
%type  <replstrs> replstrslist
%type  <replstrs> actions rmheaders accounts
%type  <re> casere retre
%type  <rule> perform
%type  <server> server
%type  <string> port to folder xstrv strv replstrv replpathv val optval
%type  <strings> stringslist pathslist
%type  <strings> domains headers maildirs mboxes groups
%type  <users> users userslist
%type  <userpass> userpass userpassreqd userpassnetrc
%type  <uid> uid user

%%

/* Rules */

/** CMDS */
cmds: /* empty */
    | cmds account
    | cmds defaction
    | cmds defmacro
    | cmds rule
    | cmds set
    | cmds close
    | cmds cache
    | cmds NONE

/* Plural/singular combinations. */
/** ACTIONP */
actionp: TOKACTION
       | TOKACTIONS
/** USERP */
userp: TOKUSER
     | TOKUSERS
/** ACCOUNTP */
accountp: TOKACCOUNT
        | TOKACCOUNTS
/** GROUPP */
groupp: TOKGROUP
      | TOKGROUPS
/** MAILDIRP */
maildirp: TOKMAILDIR
        | TOKMAILDIRS
/** MBOXP */
mboxp: TOKMBOX
     | TOKMBOXES
/** RMHEADERP */
rmheaderp: TOKREMOVEHEADER
         | TOKREMOVEHEADERS
/** HEADERP */
headerp: TOKHEADER
       | TOKHEADERS
/** DOMAINP */
domainp: TOKDOMAIN
       | TOKDOMAINS

/** VAL: <string> (char *) */
val: TOKVALUE strv
/**  [$2: strv (char *)] */
     {
	     $$ = $2;
     }
   | strv
/**  [$1: strv (char *)] */
     {
	     $$ = $1;
     }

/** OPTVAL: <string> (char *) */
optval: TOKVALUE strv
/**     [$2: strv (char *)] */
        {
		$$ = $2;
        }
      | /* empty */
	{
		$$ = NULL;
	}

/** XSTRV: <string> (char *) */
xstrv: STRCOMMAND
       {
	       $$ = run_command($1, parse_file->path);
	       xfree($1);
       }
     | STRING
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

/** STRV: <string> (char *) */
strv: xstrv
/**   [$1: xstrv (char *)] */
      {
	      $$ = $1;
      }
    | strv '+' xstrv
/**   [$1: strv (char *)] [$3: xstrv (char *)] */
      {
	      size_t	size;

	      size = strlen($1) + strlen($3) + 1;
	      $$ = xrealloc($1, 1, size);
	      strlcat($$, $3, size);
	      xfree($3);
      }

/** NUMV: <number> (long long) */
numv: NUMCOMMAND
      {
	      const char	*errstr;
	      char		*s;

	      s = run_command($1, parse_file->path);

	      $$ = strtonum(s, 0, LLONG_MAX, &errstr);
	      if (errstr != NULL)
		      yyerror("number is %s", errstr);

	      xfree(s);

	      xfree($1);
      }
    | NUMBER
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

/** REPLSTRV: <string> (char *) */
replstrv: strv
/**       [$1: strv (char *)] */
	  {
		  struct replstr	rs;

		  rs.str = $1;
		  $$ = replacestr(&rs, parse_tags, NULL, NULL);
		  xfree($1);
	  }

/** REPLPATHV: <string> (char *) */
replpathv: strv
/**        [$1: strv (char *)] */
	   {
		  struct replpath	rp;

		  rp.str = $1;
		  $$ = replacepath(&rp, parse_tags, NULL, NULL);
		  xfree($1);
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

/** EXPIRE: <number> (long long) */
expire: TOKEXPIRE time
/**     [$2: time (long long)] */
	{
#if UINT64_MAX < LLONG_MAX
		if ($2 > UINT64_MAX)
			yyerror("time too long");
#endif

		$$ = $2;
	}
      | /* empty */
	{
		$$ = -1;
	}

/** CACHE */
cache: TOKCACHE replpathv expire
/**    [$2: replpathv (char *)] [$3: expire (long long)] */
       {
	       struct cache	*cache;

	       TAILQ_FOREACH(cache, &conf.caches, entry) {
		       if (strcmp(cache->path, $2) == 0)
			       yyerror("duplicate cache path");
	       }

	       cache = xcalloc(1, sizeof *cache);
	       cache->path = $2;
	       cache->expire = $3;

	       TAILQ_INSERT_TAIL(&conf.caches, cache, entry);

	       log_debug2("added cache \"%s\": expire %lld", cache->path, $3);
       }

/** SET */
set: TOKSET TOKMAXSIZE size
/**  [$3: size (long long)] */
     {
	     if ($3 == 0)
		     yyerror("zero maximum size");
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
   | TOKSET TOKLOCKFILE replpathv
/**  [$3: replpathv (char *)] */
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
   | TOKSET TOKCMDUSER uid
/**  [$3: uid (uid_t)] */
     {
	     conf.cmd_user = $3;
     }
   | TOKSET TOKSTRIPCHARACTERS strv
/**  [$3: strv (char *)] */
     {
	     xfree(conf.strip_chars);
	     conf.strip_chars = $3;
     }
   | TOKSET TOKTIMEOUT time
/**  [$3: time (long long)] */
     {
	     if ($3 == 0)
		     yyerror("zero timeout");
	     if ($3 > INT_MAX / 1000)
		     yyerror("timeout too long: %lld", $3);
	     conf.timeout = $3 * 1000;
     }
   | TOKSET TOKQUEUEHIGH numv
/**  [$3: numv (long long)] */
     {
	     if ($3 == 0)
		     yyerror("zero queue-high");
	     if ($3 > MAXQUEUEVALUE)
		     yyerror("queue-high too big: %lld", $3);
	     if (conf.queue_low != -1 && $3 <= conf.queue_low)
		     yyerror("queue-high must be larger than queue-low");
	     conf.queue_high = $3;
     }
   | TOKSET TOKQUEUELOW numv
/**  [$3: numv (long long)] */
     {
	     if ($3 > MAXQUEUEVALUE)
		     yyerror("queue-low too big: %lld", $3);
	     if (conf.queue_high == -1)
		     yyerror("queue-high not specified");
	     if ($3 >= conf.queue_high)
		     yyerror("queue-low must be smaller than queue-high");
	     conf.queue_low = $3;
     }
   | TOKSET domains
/**  [$2: domains (struct strings *)] */
     {
	     u_int	i;

	     if (conf.domains != NULL) {
		     for (i = 0; i < ARRAY_LENGTH(conf.domains); i++)
			     xfree(ARRAY_ITEM(conf.domains, i));
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
			     xfree(ARRAY_ITEM(conf.headers, i));
		     ARRAY_FREE(conf.headers);
		     xfree(conf.headers);
	     }

	     conf.headers = $2;
     }
   | TOKSET TOKPROXY replstrv
/**  [$3: replstrv (char *)] */
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
   | TOKSET TOKVERIFYCERTS
     {
	     conf.verify_certs = 1;
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
	     conf.file_group = -1;
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
defmacro: STRMACRO '=' strv
/**       [$3: strv (char *)] */
     	  {
		  struct macro	*macro;

		  if (strlen($1) > MAXNAMESIZE)
			  yyerror("macro name too long: %s", $1);

		  macro = xmalloc(sizeof *macro);
		  strlcpy(macro->name, $1, sizeof macro->name);
		  macro->type = MACRO_STRING;
		  macro->value.str = $3;

		  if (parse_last == NULL)
			  TAILQ_INSERT_HEAD(&parse_macros, macro, entry);
		  else {
			  TAILQ_INSERT_AFTER(
			      &parse_macros, parse_last, macro, entry);
		  }

		  log_debug3("added macro \"%s\": \"%s\"", macro->name,
		      macro->value.str);
		  xfree($1);
	  }
        | NUMMACRO '=' numv
/**       [$3: numv (long long)] */
	  {
		  struct macro	*macro;

		  if (strlen($1) > MAXNAMESIZE)
			  yyerror("macro name too long: %s", $1);

		  macro = xmalloc(sizeof *macro);
		  strlcpy(macro->name, $1, sizeof macro->name);
		  macro->type = MACRO_NUMBER;
		  macro->value.num = $3;

		  if (parse_last == NULL)
			  TAILQ_INSERT_HEAD(&parse_macros, macro, entry);
		  else {
			  TAILQ_INSERT_AFTER(
			      &parse_macros, parse_last, macro, entry);
		  }

		  log_debug3("added macro \"%s\": %lld", macro->name,
		      macro->value.num);
		  xfree($1);
	  }

/** REPLSTRSLIST: <replstrs> (struct replstrs *) */
replstrslist: replstrslist strv
/**           [$1: replstrslist (struct replstrs *)] [$2: strv (char *)] */
 	      {
		      if (*$2 == '\0')
			      yyerror("empty string in list");

		      $$ = $1;
		      ARRAY_EXPAND($$, 1);
		      ARRAY_LAST($$).str = $2;
	      }
	    | strv
/**           [$1: strv (char *)] */
	      {
		      if (*$1 == '\0')
			     yyerror("empty string in list");

		      $$ = xmalloc(sizeof *$$);
		      ARRAY_INIT($$);
		      ARRAY_EXPAND($$, 1);
		      ARRAY_LAST($$).str = $1;
	      }

/** STRINGSLIST: <strings> (struct strings *) */
stringslist: stringslist replstrv
/**          [$1: stringslist (struct strings *)] [$2: replstrv (char *)] */
	     {
		     if (*$2 == '\0')
			     yyerror("empty string in list");

		     $$ = $1;
		     ARRAY_ADD($$, $2);
	     }
	   | replstrv
/**          [$1: replstrv (char *)] */
	     {
		     if (*$1 == '\0')
			     yyerror("empty string in list");

		     $$ = xmalloc(sizeof *$$);
		     ARRAY_INIT($$);
		     ARRAY_ADD($$, $1);
	     }

/** PATHSLIST: <strings> (struct strings *) */
pathslist: pathslist replpathv
/**        [$1: pathslist (struct strings *)] [$2: replpathv (char *)] */
	   {
		   if (*$2 == '\0')
			   yyerror("invalid path");

		   $$ = $1;
		   ARRAY_ADD($$, $2);
	   }
	 | replpathv
/**        [$1: replpathv (char *)] */
	   {
		   if (*$1 == '\0')
			   yyerror("invalid path");

		   $$ = xmalloc(sizeof *$$);
		   ARRAY_INIT($$);
		   ARRAY_ADD($$, $1);
	   }

/** USERSLIST: <users> (struct { ... } users) */
userslist: userslist uid
/**        [$1: userslist (struct { ... } users)] [$2: uid (uid_t)] */
	   {
		   $$ = $1;
		   ARRAY_ADD($$.users, $2);
	   }
	 | uid
/**        [$1: uid (uid_t)] */
	   {
		   $$.users = xmalloc(sizeof *$$.users);
		   ARRAY_INIT($$.users);
		   ARRAY_ADD($$.users, $1);
	   }

/** DOMAINS: <strings> (struct strings *) */
domains: domainp replstrv
/**      [$2: replstrv (char *)] */
	 {
		 if (*$2 == '\0')
			 yyerror("invalid domain");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_ADD($$, $2);
	 }
       | domainp '{' stringslist '}'
/**      [$3: stringslist (struct strings *)] */
	 {
		 $$ = $3;
	 }

/** HEADERS: <strings> (struct strings *) */
headers: headerp replstrv
/**      [$2: replstrv (char *)] */
	 {
		 if (*$2 == '\0')
			 yyerror("invalid header");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_ADD($$, $2);
	 }
       | headerp '{' stringslist '}'
/**      [$3: stringslist (struct strings *)] */
	 {
		 $$ = $3;
	 }

/** RMHEADERS: <replstrs> (struct replstrs *) */
rmheaders: rmheaderp strv
/**        [$2: strv (char *)] */
	   {
		   if (*$2 == '\0')
			   yyerror("invalid header");

		   $$ = xmalloc(sizeof *$$);
		   ARRAY_INIT($$);
		   ARRAY_EXPAND($$, 1);
		   ARRAY_LAST($$).str = $2;
	   }
	 | rmheaderp '{' replstrslist '}'
/**        [$3: replstrslist (struct replstrs *)] */
	   {
		   $$ = $3;
	   }

/** MAILDIRS: <strings> (struct strings *) */
maildirs: maildirp replpathv
/**       [$2: replpathv (char *)] */
	  {
		  if (*$2 == '\0')
			  yyerror("invalid path");

		  $$ = xmalloc(sizeof *$$);
		  ARRAY_INIT($$);
		  ARRAY_ADD($$, $2);
	  }
        | maildirp '{' pathslist '}'
/**       [$3: pathslist (struct strings *)] */
	  {
		  $$ = $3;
	  }

/** MBOXES: <strings> (struct strings *) */
mboxes: mboxp replpathv
/**     [$2: replpathv (char *)] */
        {
		if (*$2 == '\0')
			yyerror("invalid path");

		$$ = xmalloc(sizeof *$$);
		ARRAY_INIT($$);
		ARRAY_ADD($$, $2);
	}
      | mboxp '{' pathslist '}'
/**     [$3: pathslist (struct strings *)] */
	{
		$$ = $3;
	}

/** LOCK: <locks> (u_int) */
lock: TOKFCNTL
      {
	      $$ = LOCK_FCNTL;
      }
    | TOKFLOCK
      {
	      $$ = LOCK_FLOCK;
      }
    | TOKDOTLOCK
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
uid: replstrv
/**  [$1: replstrv (char *)] */
     {
	     struct passwd	*pw;

	     if (*$1 == '\0')
		     yyerror("invalid user");

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
gid: replstrv
/**  [$1: replstrv (char *)] */
     {
	     struct group	*gr;

	     if (*$1 == '\0')
		     yyerror("invalid group");

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
	      $$ = -1;
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
     | userp TOKFROMHEADERS
       {
	       $$.users = NULL;
	       $$.find_uid = 1;
       }
     | userp uid
/**    [$2: uid (uid_t)] */
       {
	       $$.users = xmalloc(sizeof *$$.users);
	       ARRAY_INIT($$.users);
	       ARRAY_ADD($$.users, $2);
	       $$.find_uid = 0;
       }
     | userp '{' userslist '}'
/**    [$3: userslist (struct { ... } users)] */
       {
	       $$ = $3;
	       $$.users = $$.users;
	       $$.find_uid = 0;
       }

/** CASERE: <re> (struct { ... } re) */
casere: TOKCASE replstrv
/**     [$2: replstrv (char *)] */
        {
		/* match case */
		$$.flags = 0;
		$$.str = $2;
        }
      | replstrv
/**     [$1: replstrv (char *)] */
        {
		/* ignore case */
		$$.flags = RE_IGNCASE;
		$$.str = $1;
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
port: TOKPORT replstrv
/**   [$2: replstrv (char *)] */
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
server: TOKSERVER replstrv port
/**     [$2: replstrv (char *)] [$3: port (char *)] */
{
		if (*$2 == '\0')
			yyerror("invalid host");

		$$.host = $2;
		$$.port = $3;
	}
      | TOKSERVER replstrv
/**     [$2: replstrv (char *)] */
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

/** ACTITEM: <actitem> (struct actitem *) */
actitem: execpipe strv
/**      [$1: execpipe (int)] [$2: strv (char *)] */
	 {
		 struct deliver_pipe_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid command");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_pipe;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->pipe = $1;
		 data->cmd.str = $2;
	 }
       | TOKREWRITE strv
/**      [$2: strv (char *)] */
	 {
		 struct deliver_rewrite_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid command");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_rewrite;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->cmd.str = $2;
	 }
       | writeappend strv
/**      [$1: writeappend (int)] [$2: strv (char *)] */
	 {
		 struct deliver_write_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid path");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_write;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->append = $1;
		 data->path.str = $2;
	 }
       | TOKMAILDIR strv
/**      [$2: strv (char *)] */
	 {
		 struct deliver_maildir_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid path");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_maildir;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->path.str = $2;
	 }
       | rmheaders
/**      [$1: rmheaders (struct replstrs *)] */
	 {
		 struct deliver_remove_header_data *data;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_remove_header;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->hdrs = $1;
	 }
       | TOKADDHEADER strv val
/**      [$2: strv (char *)] [$3: val (char *)] */
	 {
		 struct deliver_add_header_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid header");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_add_header;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->hdr.str = $2;
		 data->value.str = $3;
	 }
       | TOKMBOX strv compress
/**      [$2: strv (char *)] [$3: compress (int)] */
	 {
		 struct deliver_mbox_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid path");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_mbox;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->path.str = $2;
		 data->compress = $3;
	 }
       | TOKSMTP server to
/**      [$2: server (struct { ... } server)] [$3: to (char *)] */
	 {
		 struct deliver_smtp_data	*data;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_smtp;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->server.host = $2.host;
		 if ($2.port != NULL)
			 data->server.port = $2.port;
		 else
			 data->server.port = xstrdup("smtp");
		 data->server.ai = NULL;
		 data->to.str = $3;
	 }
       | TOKSTDOUT
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_stdout;
	 }
       | TOKTAG strv optval
/**      [$2: strv (char *)] [$3: optval (char *)] */
	 {
		 struct deliver_tag_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid tag");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_tag;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->key.str = $2;
		 data->value.str = $3;
	 }
       | TOKADDTOCACHE replpathv TOKKEY strv
/**      [$2: replpathv (char *)] [$4: strv (char *)] */
	 {
		 struct deliver_add_to_cache_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid path");
		 if (*$4 == '\0')
			 yyerror("invalid key");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_add_to_cache;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->key.str = $4;
		 data->path = $2;
	 }
       | TOKREMOVEFROMCACHE replpathv TOKKEY strv
/**      [$2: replpathv (char *)] [$4: strv (char *)] */
	 {
		 struct deliver_remove_from_cache_data	*data;

		 if (*$2 == '\0')
			 yyerror("invalid path");
		 if (*$4 == '\0')
			 yyerror("invalid key");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_remove_from_cache;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->key.str = $4;
		 data->path = $2;
	 }
       | actions
/**      [$1: actions (struct replstrs *)] */
	 {
		 struct deliver_action_data	*data;

		 /*
		  * This is a special-case, handled when the list of delivery
		  * targets is resolved rather than by calling a deliver
		  * function, so the deliver pointer is NULL.
		  */
		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = NULL;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->actions = $1;
 	 }
       | TOKDROP
         {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_drop;
	 }
       | TOKKEEP
         {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_keep;
	 }

/** ACTLIST: <actlist> (struct actlist *) */
actlist: actlist actitem
/**      [$1: actlist (struct actlist *)] [$2: actitem (struct actitem *)] */
	 {
		 $$ = $1;

		 TAILQ_INSERT_TAIL($$, $2, entry);
		 $2->idx = parse_actionidx++;
	 }
       | actitem
/**      [$1: actitem (struct actitem *)] */
	 {
		 $$ = xmalloc(sizeof *$$);
		 TAILQ_INIT($$);

		 TAILQ_INSERT_HEAD($$, $1, entry);
		 $1->idx = 0;

		 parse_actionidx = 1;
	 }

/** DEFACTION */
defaction: TOKACTION replstrv users actitem
/**        [$2: replstrv (char *)] [$3: users (struct { ... } users)] */
/**        [$4: actitem (struct actitem *)] */
	   {
		   struct action	*t;

		   if (strlen($2) >= MAXNAMESIZE)
			   yyerror("action name too long: %s", $2);
		   if (*$2 == '\0')
			   yyerror("invalid action name");
		   if (find_action($2) != NULL)
			   yyerror("duplicate action: %s", $2);

		   t = xmalloc(sizeof *t);
		   strlcpy(t->name, $2, sizeof t->name);

		   t->list = xmalloc(sizeof *t->list);
		   TAILQ_INIT(t->list);
		   TAILQ_INSERT_HEAD(t->list, $4, entry);
		   $4->idx = 0;

		   t->users = $3.users;
		   t->find_uid = $3.find_uid;
		   TAILQ_INSERT_TAIL(&conf.actions, t, entry);

		   print_action(t);

		   xfree($2);
	   }
	 | TOKACTION replstrv users '{' actlist '}'
/**        [$2: replstrv (char *)] [$3: users (struct { ... } users)] */
/**        [$5: actlist (struct actlist *)] */
	   {
		   struct action	*t;

		   if (strlen($2) >= MAXNAMESIZE)
			   yyerror("action name too long: %s", $2);
		   if (*$2 == '\0')
			   yyerror("invalid action name");
		   if (find_action($2) != NULL)
			   yyerror("duplicate action: %s", $2);

		   t = xmalloc(sizeof *t);
		   strlcpy(t->name, $2, sizeof t->name);

		   t->list = $5;

		   t->users = $3.users;
		   t->find_uid = $3.find_uid;
		   TAILQ_INSERT_TAIL(&conf.actions, t, entry);

		   print_action(t);

		   xfree($2);
	   }

/** ACCOUNTS: <replstrs> (struct replstrs *) */
accounts: accountp strv
/**       [$2: strv (char *)] */
	  {
		  if (*$2 == '\0')
			  yyerror("invalid account name");
		  if (!have_accounts($2))
			  yyerror("no matching accounts: %s", $2);

		  $$ = xmalloc(sizeof *$$);
		  ARRAY_INIT($$);
		  ARRAY_EXPAND($$, 1);
		  ARRAY_LAST($$).str = $2;
	  }
	| accountp '{' replstrslist '}'
/**       [$3: replstrslist (struct replstrs *)] */
	  {
		  $$ = $3;
	  }

/** ACTIONS: <replstrs> (struct replstrs *) */
actions: actionp strv
/**      [$2: strv (char *)] */
	 {
		 if (*$2 == '\0')
			 yyerror("invalid action name");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_EXPAND($$, 1);
		 ARRAY_LAST($$).str = $2;
	 }
       | actionp '{' replstrslist '}'
/**      [$3: replstrslist (struct replstrs *)] */
         {
		 $$ = $3;
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

/** RETRE: <re> (struct { ... } re) */
retre: casere
/**    [$1: casere (struct { ... } re)] */
       {
	       $$ = $1;
       }
     | /* empty */
       {
	       $$.str = NULL;
       }

/** LTGT: <cmp> (enum cmp) */
ltgt: '<'
     {
	     $$ = CMP_LT;
     }
   | '>'
     {
	     $$ = CMP_GT;
     }

/** EQNE: <cmp> (enum cmp) */
eqne: TOKEQ
      {
	      $$ = CMP_EQ;
      }
    | TOKNE
      {
	      $$ = CMP_NE;
      }

/** CMP: <cmp> (enum cmp) */
cmp: ltgt
/**  [$1: ltgt (enum cmp)] */
     {
	     $$ = $1;
     }
   | eqne
/**  [$1: eqne (enum cmp)] */
     {
	     $$ = $1;
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

/** WRITEAPPEND: <flag> (int) */
writeappend: TOKWRITE
	     {
		     $$ = 0;
	     }
           | TOKAPPEND
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
expritem: not TOKALL
/**       [$1: not (int)] */
	  {
		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_all;
		  $$->inverted = $1;
	  }
	| not casere area
/**       [$1: not (int)] [$2: casere (struct { ... } re)] */
/**       [$3: area (enum area)] */
          {
		  struct match_regexp_data	*data;
		  char				*cause;

		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_regexp;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->area = $3;

		  if (re_compile(&data->re, $2.str, $2.flags, &cause) != 0)
			  yyerror("%s", cause);
		  xfree($2.str);
	  }
        | not accounts
/**       [$1: not (int)] [$2: accounts (struct replstrs *)] */
	  {
		  struct match_account_data	*data;

		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_account;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->accounts = $2;
	  }
        | not execpipe strv user TOKRETURNS '(' retrc ',' retre ')'
/**       [$1: not (int)] [$2: execpipe (int)] [$3: strv (char *)] */
/**       [$4: user (uid_t)] [$7: retrc (long long)] */
/**       [$9: retre (struct { ... } re)] */
	  {
		  struct match_command_data	*data;
		  char				*cause;

		  if (*$3 == '\0' || ($3[0] == '|' && $3[1] == '\0'))
			  yyerror("invalid command");
		  if ($7 == -1 && $9.str == NULL)
			  yyerror("return code or regexp must be specified");

		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_command;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->uid = $4;
		  data->pipe = $2;
		  data->cmd.str = $3;

		  data->ret = $7;

		  if ($9.str != NULL) {
			  if (re_compile(
			      &data->re, $9.str, $9.flags, &cause) != 0)
				  yyerror("%s", cause);
			  xfree($9.str);
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

		  data->tag.str = $3;
	  }
        | not TOKSIZE ltgt size
/**       [$1: not (int)] [$3: ltgt (enum cmp)] [$4: size (long long)] */
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
        | not TOKSTRING strv TOKTO casere
/**       [$1: not (int)] [$3: strv (char *)] */
/**       [$5: casere (struct { ... } re)] */
	  {
		  struct match_string_data	*data;
		  char				*cause;

		  if (*$3 == '\0')
			  yyerror("invalid string");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_string;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->str.str = $3;
		  if (re_compile(
		      &data->re, $5.str, $5.flags|RE_NOSUBST, &cause) != 0)
			  yyerror("%s", cause);
		  xfree($5.str);
	  }
	| not TOKINCACHE replpathv TOKKEY strv
/**       [$1: not (int)] [$3: replpathv (char *)] [$5: strv (char *)] */
	  {
		  struct match_in_cache_data	*data;

		  if (*$3 == '\0')
			  yyerror("invalid path");
		  if (*$5 == '\0')
			  yyerror("invalid key");

		  $$ = xcalloc(1, sizeof *$$);

		  $$->match = &match_in_cache;
		  $$->inverted = $1;

		  data = xcalloc(1, sizeof *data);
		  $$->data = data;

		  data->key.str = $5;
		  data->path = $3;
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
        | not TOKAGE ltgt time
/**       [$1: not (int)] [$3: ltgt (enum cmp)] [$4: time (long long)] */
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
        | not TOKATTACHMENT TOKCOUNT cmp numv
/**       [$1: not (int)] [$4: cmp (enum cmp)] [$5: numv (long long)] */
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
        | not TOKATTACHMENT TOKTOTALSIZE ltgt size
/**       [$1: not (int)] [$4: ltgt (enum cmp)] [$5: size (long long)] */
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
        | not TOKATTACHMENT TOKANYSIZE ltgt size
/**       [$1: not (int)] [$4: ltgt (enum cmp)] [$5: size (long long)] */
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
		  data->value.str.str = $4;
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
		  data->value.str.str = $4;
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

/** PERFORM: <rule> (struct rule *) */
perform: users actionp actitem cont
/**      [$1: users (struct { ... } users)] [$3: actitem (struct actitem *)] */
/**      [$4: cont (int)] */
	 {
		 struct action	*t;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = parse_ruleidx++;
		 $$->actions = NULL;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = !$4;
		 $$->users = $1.users;
		 $$->find_uid = $1.find_uid;

		 t = $$->lambda = xcalloc(1, sizeof *$$->lambda);
		 xsnprintf(t->name, sizeof t->name, "<rule %u>", $$->idx);
		 t->users = NULL;
		 t->find_uid = 0;
		 t->list = xmalloc(sizeof *t->list);
		 TAILQ_INIT(t->list);
		 TAILQ_INSERT_HEAD(t->list, $3, entry);
		 $3->idx = 0;

		 if (parse_rule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&parse_rule->rules, $$, entry);
	 }
       | users actionp '{' actlist '}' cont
/**      [$1: users (struct { ... } users)] */
/**      [$4: actlist (struct actlist *)] [$6: cont (int)] */
	 {
		 struct action	*t;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = parse_ruleidx++;
		 $$->actions = NULL;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = !$6;
		 $$->users = $1.users;
		 $$->find_uid = $1.find_uid;

		 t = $$->lambda = xcalloc(1, sizeof *$$->lambda);
		 xsnprintf(t->name, sizeof t->name, "<rule %u>", $$->idx);
		 t->users = NULL;
		 t->find_uid = 0;
		 t->list = $4;

		 if (parse_rule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&parse_rule->rules, $$, entry);
	 }
       | users actions cont
/**      [$1: users (struct { ... } users)] */
/**      [$2: actions (struct replstrs *)] [$3: cont (int)] */
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = parse_ruleidx++;
		 $$->lambda = NULL;
		 $$->actions = $2;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = !$3;
		 $$->users = $1.users;
		 $$->find_uid = $1.find_uid;

		 if (parse_rule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&parse_rule->rules, $$, entry);
	 }
       | '{'
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = parse_ruleidx++;
		 $$->lambda = NULL;
		 $$->actions = NULL;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = 0;
		 $$->users = NULL;
		 $$->find_uid = 0;

		 if (parse_rule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&parse_rule->rules, $$, entry);

		 ARRAY_ADD(&parse_rulestack, parse_rule);
		 parse_rule = $$;
	 }

/** CLOSE */
close: '}'
       {
	       if (parse_rule == NULL)
		       yyerror("missing {");

	       parse_rule = ARRAY_LAST(&parse_rulestack);
	       ARRAY_TRUNC(&parse_rulestack, 1);
       }

/** RULE */
rule: TOKMATCH expr perform
/**   [$2: expr (struct expr *)] [$3: perform (struct rule *)] */
      {
	      $3->expr = $2;
	      print_rule($3);
      }

/** FOLDER: <string> (char *) */
folder: /* empty */
        {
		$$ = NULL;
        }
      | TOKFOLDER replstrv
/**     [$2: replstrv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid folder");

		$$ = $2;
	}

/** GROUPS: <strings> (struct strings *) */
groups: groupp replstrv
/**     [$2: replstrv (char *)] */
	{
		if (*$2 == '\0')
			yyerror("invalid group");

		$$ = xmalloc(sizeof *$$);
		ARRAY_INIT($$);
		ARRAY_ADD($$, $2);
	}
      | groupp '{' stringslist '}'
/**     [$3: stringslist (struct strings *)] */
        {
		$$ = $3;
	}

/** VERIFY: <flag> (int) */
verify: TOKNOVERIFY
	{
		$$ = 0;
	}
      | /* empty */
	{
		$$ = 1;
	}

/** APOP: <flag> (int) */
apop: TOKNOAPOP
      {
	      $$ = 0;
      }
    | /* empty */
      {
	      $$ = 1;
      }

/** ONLY: <only> (enum fetch_only) */
only: TOKNEWONLY
      {
	      $$ = FETCH_ONLY_NEW;
      }
    | TOKOLDONLY
      {
	      $$ = FETCH_ONLY_OLD;
      }

/** POPTYPE: <flag> (int) */
poptype: TOKPOP3
         {
		 $$ = 0;
         }
       | TOKPOP3S
	 {
		 $$ = 1;
	 }

/** IMAPTYPE: <flag> (int) */
imaptype: TOKIMAP
          {
		  $$ = 0;
          }
        | TOKIMAPS
	  {
		  $$ = 1;
	  }

/** NNTPTYPE: <flag> (int) */
nntptype: TOKNNTP
          {
		  $$ = 0;
          }
        | TOKNNTPS
	  {
		  $$ = 1;
	  }

/** USERPASSNETRC: <userpass> (struct { ... } userpass) */
userpassnetrc: TOKUSER replstrv TOKPASS replstrv
/**            [$2: replstrv (char *)] [$4: replstrv (char *)] */
	       {
		       if (*$2 == '\0')
			       yyerror("invalid user");
		       if (*$4 == '\0')
			       yyerror("invalid pass");

		       $$.user = $2;
		       $$.user_netrc = 0;
		       $$.pass = $4;
		       $$.pass_netrc = 0;
	       }
	     | /* empty */
	       {
		       $$.user = NULL;
		       $$.user_netrc = 1;
		       $$.pass = NULL;
		       $$.pass_netrc = 1;
	       }
	     | TOKUSER replstrv
/**            [$2: replstrv (char *)] */
	       {
		       if (*$2 == '\0')
			       yyerror("invalid user");

		       $$.user = $2;
		       $$.user_netrc = 0;
		       $$.pass = NULL;
		       $$.pass_netrc = 1;
	       }
	     | TOKPASS replstrv
/**            [$2: replstrv (char *)] */
	       {
		       if (*$2 == '\0')
			       yyerror("invalid pass");

		       $$.user = NULL;
		       $$.user_netrc = 1;
		       $$.pass = $2;
		       $$.pass_netrc = 0;
	       }

/** USERPASSREQD: <userpass> (struct { ... } userpass) */
userpassreqd: TOKUSER replstrv TOKPASS replstrv
/**           [$2: replstrv (char *)] [$4: replstrv (char *)] */
	      {
		      if (*$2 == '\0')
			      yyerror("invalid user");
		      if (*$4 == '\0')
			      yyerror("invalid pass");

		      $$.user = $2;
		      $$.user_netrc = 0;
		      $$.pass = $4;
		      $$.pass_netrc = 0;
	      }

/** USERPASS: <userpass> (struct { ... } userpass) */
userpass: userpassreqd
/**       [$1: userpassreqd (struct { ... } userpass)] */
	  {
		  $$.user = $1.user;
		  $$.user_netrc = $1.user_netrc;
		  $$.pass = $1.pass;
		  $$.pass_netrc = $1.pass_netrc;
	  }
	| /* empty */
	  {
		  $$.user = NULL;
		  $$.user_netrc = 0;
		  $$.pass = NULL;
		  $$.pass_netrc = 0;
	  }

/** POPONLY: <poponly> (struct { ... } poponly) */
poponly: only TOKCACHE replpathv
/**      [$1: only (enum fetch_only)] [$3: replpathv (char *)] */
	 {
		 $$.path = $3;
		 $$.only = $1;
	 }
       | /* empty */
	 {
		 $$.path = NULL;
		 $$.only = FETCH_ONLY_ALL;
	 }

/** IMAPONLY: <only> (enum fetch_only) */
imaponly: only
/**       [$1: only (enum fetch_only)] */
	  {
		  $$ = $1;
	  }
        | /* empty */
	  {
		  $$ = FETCH_ONLY_ALL;
	  }

/** FETCHTYPE: <fetch> (struct { ... } fetch) */
fetchtype: poptype server userpassnetrc poponly apop verify
/**        [$1: poptype (int)] [$2: server (struct { ... } server)] */
/**        [$3: userpassnetrc (struct { ... } userpass)] */
/**        [$4: poponly (struct { ... } poponly)] [$5: apop (int)] [$6: verify (int)] */
           {
		   struct fetch_pop3_data	*data;

		   $$.fetch = &fetch_pop3;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;

		   if ($3.user_netrc && $3.pass_netrc)
			  find_netrc($2.host, &data->user, &data->pass);
		   else {
			   if ($3.user_netrc)
				   find_netrc($2.host, &data->user, NULL);
			   else
				   data->user = $3.user;
			   if ($3.pass_netrc)
				   find_netrc($2.host, NULL, &data->pass);
			   else
				   data->pass = $3.pass;
		   }

		   data->server.ssl = $1;
		   data->server.verify = $6;
		   data->server.host = $2.host;
		   if ($2.port != NULL)
			   data->server.port = $2.port;
		   else if ($1)
			   data->server.port = xstrdup("pop3s");
		   else
			   data->server.port = xstrdup("pop3");
		   data->server.ai = NULL;
		   data->apop = $5;

		   data->path = $4.path;
		   data->only = $4.only;
	   }
	 | TOKPOP3 TOKPIPE replstrv userpassreqd poponly apop
/**        [$3: replstrv (char *)] */
/**        [$4: userpassreqd (struct { ... } userpass)] */
/**        [$5: poponly (struct { ... } poponly)] [$6: apop (int)] */
	   {
		   struct fetch_pop3_data	*data;

		   $$.fetch = &fetch_pop3pipe;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->user = $4.user;
		   data->pass = $4.pass;
		   data->pipecmd = $3;
		   if (data->pipecmd == NULL || *data->pipecmd == '\0')
			   yyerror("invalid pipe command");
		   data->apop = $6;
		   data->path = $5.path;
		   data->only = $5.only;
	   }
         | imaptype server userpassnetrc folder imaponly verify
/**        [$1: imaptype (int)] [$2: server (struct { ... } server)] */
/**        [$3: userpassnetrc (struct { ... } userpass)] [$4: folder (char *)] */
/**        [$5: imaponly (enum fetch_only)] [$6: verify (int)] */
           {
		   struct fetch_imap_data	*data;

		   if ($4 != NULL && *$4 == '\0')
			   yyerror("invalid folder");

		   $$.fetch = &fetch_imap;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;

		   if ($3.user_netrc && $3.pass_netrc)
			  find_netrc($2.host, &data->user, &data->pass);
		   else {
			   if ($3.user_netrc)
				   find_netrc($2.host, &data->user, NULL);
			   else
				   data->user = $3.user;
			   if ($3.pass_netrc)
				   find_netrc($2.host, NULL, &data->pass);
			   else
				   data->pass = $3.pass;
		   }

		   data->folder = $4 == NULL ? xstrdup("INBOX") : $4;
		   data->server.ssl = $1;
		   data->server.verify = $6;
		   data->server.host = $2.host;
		   if ($2.port != NULL)
			   data->server.port = $2.port;
		   else if ($1)
			   data->server.port = xstrdup("imaps");
		   else
			   data->server.port = xstrdup("imap");
		   data->server.ai = NULL;
		   data->only = $5;
	   }
	 | TOKIMAP TOKPIPE replstrv userpass folder imaponly
/**        [$3: replstrv (char *)] */
/**        [$4: userpass (struct { ... } userpass)] [$5: folder (char *)] */
/**        [$6: imaponly (enum fetch_only)] */
	   {
		   struct fetch_imap_data	*data;

		   if ($5 != NULL && *$5 == '\0')
			   yyerror("invalid folder");

		   $$.fetch = &fetch_imappipe;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->user = $4.user;
		   data->pass = $4.pass;
		   data->folder = $5 == NULL ? xstrdup("INBOX") : $5;
		   data->pipecmd = $3;
		   if (data->pipecmd == NULL || *data->pipecmd == '\0')
			   yyerror("invalid pipe command");
		   data->only = $6;
	   }
	 | TOKSTDIN
	   {
		   $$.fetch = &fetch_stdin;
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
         | mboxes
/**        [$1: mboxes (struct strings *)] */
	   {
		   struct fetch_mbox_data	*data;

		   $$.fetch = &fetch_mbox;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->mboxes = $1;
	   }
	 | nntptype server groups TOKCACHE replpathv verify
/**        [$1: nntptype (int)] [$2: server (struct { ... } server)] */
/**        [$3: groups (struct strings *)] [$5: replpathv (char *)] */
/**        [$6: verify (int)] */
           {
		   struct fetch_nntp_data	*data;
		   char				*group;

		   if (*$5 == '\0')
			   yyerror("invalid cache");

		   $$.fetch = &fetch_nntp;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->names = $3;

		   if (ARRAY_LENGTH($3) == 1)
			   group = ARRAY_FIRST($3);
		   else
			   group = NULL;
		   data->path = $5;
		   if (data->path == NULL || *data->path == '\0')
			   yyerror("invalid cache");

		   data->server.ssl = $1;
		   data->server.verify = $6;
		   data->server.host = $2.host;
		   if ($2.port != NULL)
			   data->server.port = $2.port;
		   else if ($1)
                           data->server.port = xstrdup("nntps");
                   else
			   data->server.port = xstrdup("nntp");
		   data->server.ai = NULL;
	   }

/** ACCOUNT */
account: TOKACCOUNT replstrv disabled users fetchtype keep
/**      [$2: replstrv (char *)] [$3: disabled (int)] */
/**      [$4: users (struct { ... } users)] [$5: fetchtype (struct { ... } fetch)] */
/**      [$6: keep (int)] */
         {
		 struct account		*a;
		 char			*su, desc[DESCBUFSIZE];

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

		 if (a->users != NULL)
			 su = fmt_users(" users=", a->users);
		 else
			 su = xstrdup("");
		 a->fetch->desc(a, desc, sizeof desc);
		 log_debug2("added account \"%s\":%s fetch=%s", a->name, su,
		     desc);
		 xfree(su);

		 xfree($2);
	 }

%%

/* Programs */
