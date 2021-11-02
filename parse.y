/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicholas.marriott@gmail.com>
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
	add_tag(&parse_tags, "home", "%s", conf.user_home);

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
	log_vwrite(LOG_CRIT, s, ap);
	va_end(ap);

	exit(1);
}
%}

%token TOKACCOUNT
%token TOKACCOUNTS
%token TOKACTION
%token TOKACTIONS
%token TOKADDHEADER
%token TOKADDTOCACHE
%token TOKAGE
%token TOKALL
%token TOKALLOWMANY
%token TOKAND
%token TOKANYNAME
%token TOKANYSIZE
%token TOKANYTYPE
%token TOKAPPEND
%token TOKATTACHMENT
%token TOKBODY
%token TOKBYTES
%token TOKCACHE
%token TOKCASE
%token TOKCMDUSER
%token TOKCOMPRESS
%token TOKCONTINUE
%token TOKCOUNT
%token TOKDAYS
%token TOKDEFUSER
%token TOKDELTOOBIG
%token TOKDISABLED
%token TOKDOMAIN
%token TOKDOTLOCK
%token TOKDROP
%token TOKEQ
%token TOKEXEC
%token TOKEXPIRE
%token TOKFCNTL
%token TOKFILEGROUP
%token TOKFILEUMASK
%token TOKFLOCK
%token TOKFOLDER
%token TOKFOLDERS
%token TOKFROM
%token TOKGIGABYTES
%token TOKGROUP
%token TOKGROUPS
%token TOKHEADER
%token TOKHEADERS
%token TOKHOURS
%token TOKIGNOREERRORS
%token TOKIMAP
%token TOKIMAPS
%token TOKIMPLACT
%token TOKIN
%token TOKINCACHE
%token TOKINSECURE
%token TOKINVALID
%token TOKKEEP
%token TOKKEY
%token TOKKILOBYTES
%token TOKLMTP
%token TOKLOCKFILE
%token TOKLOCKTIMEOUT
%token TOKLOCKTYPES
%token TOKLOCKWAIT
%token TOKLOOKUPORDER
%token TOKMAILDIR
%token TOKMAILDIRS
%token TOKMATCH
%token TOKMATCHED
%token TOKMAXSIZE
%token TOKMBOX
%token TOKMBOXES
%token TOKMEGABYTES
%token TOKMINUTES
%token TOKMONTHS
%token TOKNE
%token TOKNEWONLY
%token TOKNNTP
%token TOKNNTPS
%token TOKNOAPOP
%token TOKNOCRAMMD5
%token TOKNOCREATE
%token TOKNOLOGIN
%token TOKNONE
%token TOKNOPLAIN
%token TOKNORECEIVED
%token TOKNOT
%token TOKNOUIDL
%token TOKNOVERIFY
%token TOKXOAUTH2
%token TOKOAUTHBEARER
%token TOKOLDONLY
%token TOKOR
%token TOKPARALLELACCOUNTS
%token TOKPASS
%token TOKPASSWD
%token TOKPIPE
%token TOKPOP3
%token TOKPOP3S
%token TOKPORT
%token TOKPROXY
%token TOKPURGEAFTER
%token TOKQUEUEHIGH
%token TOKQUEUELOW
%token TOKREMOVEFROMCACHE
%token TOKREMOVEHEADER
%token TOKREMOVEHEADERS
%token TOKRETURNS
%token TOKREWRITE
%token TOKSECONDS
%token TOKSERVER
%token TOKSET
%token TOKSIZE
%token TOKSMTP
%token TOKSTARTTLS
%token TOKSTDIN
%token TOKSTDOUT
%token TOKSTRING
%token TOKSTRIPCHARACTERS
%token TOKTAG
%token TOKTAGGED
%token TOKTIMEOUT
%token TOKTO
%token TOKTOTALSIZE
%token TOKUNMATCHED
%token TOKUSER
%token TOKUSERS
%token TOKVALUE
%token TOKVERIFYCERTS
%token TOKWEEKS
%token TOKWRITE
%token TOKYEARS

%union
{
	long long		 number;
	char			*string;
	int			 flag;
	u_int			 locks;
	struct {
		struct fetch	*fetch;
		void		*data;
	} fetch;
	struct {
		char		*host;
		char		*port;
	} server;
	enum area		 area;
	enum exprop		 exprop;
	struct actitem		*actitem;
	struct actlist		*actlist;
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
	gid_t			 localgid;
	enum cmp		 cmp;
	struct rule		*rule;
	struct {
		char		*user;
		int		 user_netrc;
		char		*pass;
		int		 pass_netrc;
	} userpass;
	userfunction		 ufn;
	struct userfunctions	*ufns;
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
%type  <flag> apop poptype imaptype nntptype nocrammd5 noplain nologin uidl
%type  <flag> starttls insecure oauthbearer xoauth2
%type  <localgid> localgid
%type  <locks> lock locklist
%type  <number> size time numv retrc expire
%type  <only> only imaponly
%type  <poponly> poponly
%type  <replstrs> replstrslist actions rmheaders accounts users
%type  <re> casere retre
%type  <rule> perform
%type  <server> server
%type  <string> port to from xstrv strv replstrv replpathv val optval folder1
%type  <string> user
%type  <strings> stringslist pathslist maildirs mboxes groups folders folderlist
%type  <userpass> userpass userpassreqd userpassnetrc
%type  <ufn> ufn
%type  <ufns> ufnlist

%%

/* Rules */

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
actionp: TOKACTION
       | TOKACTIONS
userp: TOKUSER
     | TOKUSERS
accountp: TOKACCOUNT
	| TOKACCOUNTS
groupp: TOKGROUP
      | TOKGROUPS
folderp: TOKFOLDER
       | TOKFOLDERS
maildirp: TOKMAILDIR
	| TOKMAILDIRS
mboxp: TOKMBOX
     | TOKMBOXES
rmheaderp: TOKREMOVEHEADER
	 | TOKREMOVEHEADERS

val: TOKVALUE strv
     {
	     $$ = $2;
     }
   | strv
     {
	     $$ = $1;
     }

optval: TOKVALUE strv
	{
		$$ = $2;
	}
      | /* empty */
	{
		$$ = NULL;
	}

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

strv: xstrv
      {
	      $$ = $1;
      }
    | strv '+' xstrv
      {
	      size_t	size;

	      size = strlen($1) + strlen($3) + 1;
	      $$ = xrealloc($1, 1, size);
	      strlcat($$, $3, size);
	      xfree($3);
      }

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

replstrv: strv
	  {
		  struct replstr	 rs;
		  struct userdata	*ud;

		  if ((ud = user_lookup(conf.def_user, conf.user_order)) != NULL)
			  update_tags(&parse_tags, ud);
		  rs.str = $1;
		  $$ = replacestr(&rs, parse_tags, NULL, NULL);
		  xfree($1);
	  }

replpathv: strv
	   {
		  struct replpath	 rp;
		  struct userdata	*ud;

		  if ((ud = user_lookup(conf.def_user, conf.user_order)) != NULL)
			  update_tags(&parse_tags, ud);
		  rp.str = $1;
		  $$ = replacepath(&rp, parse_tags, NULL, NULL, conf.user_home);
		  xfree($1);
	   }

size: numv
      {
	      $$ = $1;
      }
    | numv TOKBYTES
      {
	      $$ = $1;
      }
    | numv TOKKILOBYTES
      {
	      if ($1 > LLONG_MAX / 1024)
		      yyerror("size is too big");
	      $$ = $1 * 1024;
      }
    | numv TOKMEGABYTES
      {
	      if ($1 > LLONG_MAX / (1024 * 1024))
		      yyerror("size is too big");
	      $$ = $1 * (1024 * 1024);
      }
    | numv TOKGIGABYTES
      {
	      if ($1 > LLONG_MAX / (1024 * 1024 * 1024))
		      yyerror("size is too big");
	      $$ = $1 * (1024 * 1024 * 1024);
      }

time: numv
      {
	      $$ = $1;
      }
    | numv TOKHOURS
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

expire: TOKEXPIRE time
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

cache: TOKCACHE replpathv expire
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

set: TOKSET TOKMAXSIZE size
     {
	     if ($3 == 0)
		     yyerror("zero maximum size");
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
   | TOKSET TOKLOCKFILE replpathv
     {
	     if (conf.lock_file != NULL)
		     xfree(conf.lock_file);
	     conf.lock_file = $3;
     }
   | TOKSET TOKLOCKWAIT
     {
	     conf.lock_wait = 1;
     }
   | TOKSET TOKLOCKTIMEOUT time
     {
	     conf.lock_timeout = $3;
     }
   | TOKSET TOKDELTOOBIG
     {
	     conf.del_big = 1;
     }
   | TOKSET TOKIGNOREERRORS
     {
	     conf.ignore_errors = 1;
     }
   | TOKSET TOKALLOWMANY
     {
	     conf.allow_many = 1;
     }
   | TOKSET TOKDEFUSER strv
     {
	     if (conf.def_user == NULL)
		     conf.def_user = $3;
     }
   | TOKSET TOKCMDUSER strv
     {
	     if (conf.cmd_user == NULL)
		     conf.cmd_user = $3;
     }
   | TOKSET TOKSTRIPCHARACTERS strv
     {
	     xfree(conf.strip_chars);
	     conf.strip_chars = $3;
     }
   | TOKSET TOKTIMEOUT time
     {
	     if ($3 == 0)
		     yyerror("zero timeout");
	     if ($3 > INT_MAX / 1000)
		     yyerror("timeout too long: %lld", $3);
	     conf.timeout = $3 * 1000;
     }
   | TOKSET TOKQUEUEHIGH numv
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
     {
	     if ($3 > MAXQUEUEVALUE)
		     yyerror("queue-low too big: %lld", $3);
	     if (conf.queue_high == -1)
		     yyerror("queue-high not specified");
	     if ($3 >= conf.queue_high)
		     yyerror("queue-low must be smaller than queue-high");
	     conf.queue_low = $3;
     }
   | TOKSET TOKPARALLELACCOUNTS numv
     {
	     if ($3 > INT_MAX)
		     yyerror("parallel-accounts too big: %lld", $3);
	     if ($3 == 0)
		     yyerror("parallel-accounts cannot be zero");
	     conf.max_accts = $3;
     }
   | TOKSET TOKPROXY replstrv
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
   | TOKSET TOKNOCREATE
     {
	     conf.no_create = 1;
     }
   | TOKSET TOKFILEGROUP TOKUSER
     {
	     conf.file_group = -1;
     }
   | TOKSET TOKFILEGROUP localgid
     {
	     conf.file_group = $3;
     }
   | TOKSET TOKFILEUMASK TOKUSER
     {
	     conf.file_umask = umask(0);
	     umask(conf.file_umask);
     }
   | TOKSET TOKLOOKUPORDER ufnlist
     {
	     ARRAY_FREEALL(conf.user_order);
	     conf.user_order = $3;
     }
   | TOKSET TOKFILEUMASK numv
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

defmacro: STRMACRO '=' strv
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

replstrslist: replstrslist strv
	      {
		      if (*$2 == '\0')
			      yyerror("empty string in list");

		      $$ = $1;
		      ARRAY_EXPAND($$, 1);
		      ARRAY_LAST($$).str = $2;
	      }
	    | strv
	      {
		      if (*$1 == '\0')
			     yyerror("empty string in list");

		      $$ = xmalloc(sizeof *$$);
		      ARRAY_INIT($$);
		      ARRAY_EXPAND($$, 1);
		      ARRAY_LAST($$).str = $1;
	      }

stringslist: stringslist replstrv
	     {
		     if (*$2 == '\0')
			     yyerror("empty string in list");

		     $$ = $1;
		     ARRAY_ADD($$, $2);
	     }
	   | replstrv
	     {
		     if (*$1 == '\0')
			     yyerror("empty string in list");

		     $$ = xmalloc(sizeof *$$);
		     ARRAY_INIT($$);
		     ARRAY_ADD($$, $1);
	     }

pathslist: pathslist replpathv
	   {
		   if (*$2 == '\0')
			   yyerror("invalid path");

		   $$ = $1;
		   ARRAY_ADD($$, $2);
	   }
	 | replpathv
	   {
		   if (*$1 == '\0')
			   yyerror("invalid path");

		   $$ = xmalloc(sizeof *$$);
		   ARRAY_INIT($$);
		   ARRAY_ADD($$, $1);
	   }

ufn: TOKPASSWD
     {
	     $$ = &passwd_lookup;
     }

ufnlist: ufnlist ufn
	 {
		 $$ = $1;
		 ARRAY_ADD($$, $2);
	 }
       | ufn
	 {
		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_ADD($$, $1);
	 }

rmheaders: rmheaderp strv
	   {
		   if (*$2 == '\0')
			   yyerror("invalid header");

		   $$ = xmalloc(sizeof *$$);
		   ARRAY_INIT($$);
		   ARRAY_EXPAND($$, 1);
		   ARRAY_LAST($$).str = $2;
	   }
	 | rmheaderp '{' replstrslist '}'
	   {
		   $$ = $3;
	   }

maildirs: maildirp replpathv
	  {
		  if (*$2 == '\0')
			  yyerror("invalid path");

		  $$ = xmalloc(sizeof *$$);
		  ARRAY_INIT($$);
		  ARRAY_ADD($$, $2);
	  }
	| maildirp '{' pathslist '}'
	  {
		  $$ = $3;
	  }

mboxes: mboxp replpathv
	{
		if (*$2 == '\0')
			yyerror("invalid path");

		$$ = xmalloc(sizeof *$$);
		ARRAY_INIT($$);
		ARRAY_ADD($$, $2);
	}
      | mboxp '{' pathslist '}'
	{
		$$ = $3;
	}

folders: folderp replstrv
	 {
		 if (*$2 == '\0')
			 yyerror("invalid folder");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_ADD($$, $2);
	 }
       | folderp '{' stringslist '}'
	 {
		 $$ = $3;
	 }

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

localgid: replstrv
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

user: /* empty */
      {
	      $$ = NULL;
      }
    | TOKUSER strv
      {
	      $$ = $2;
      }

users: /* empty */
       {
	       $$ = NULL;
       }
     | userp strv
       {
	       $$ = xmalloc(sizeof *$$);
	       ARRAY_INIT($$);
	       ARRAY_EXPAND($$, 1);
	       ARRAY_LAST($$).str = $2;
       }
     | userp '{' replstrslist '}'
       {
	       $$ = $3;
       }

casere: TOKCASE replstrv
	{
		/* match case */
		$$.flags = 0;
		$$.str = $2;
	}
      | replstrv
	{
		/* ignore case */
		$$.flags = RE_IGNCASE;
		$$.str = $1;
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

port: TOKPORT replstrv
      {
	      if (*$2 == '\0')
		      yyerror("invalid port");

	      $$ = $2;
      }
    | TOKPORT numv
      {
	      if ($2 == 0 || $2 > 65535)
		      yyerror("invalid port");

	      xasprintf(&$$, "%lld", $2);
      }

server: TOKSERVER replstrv port
{
		if (*$2 == '\0')
			yyerror("invalid host");

		$$.host = $2;
		$$.port = $3;
	}
      | TOKSERVER replstrv
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
	    $$ = $2;
    }

from: /* empty */
      {
	      $$ = NULL;
      }
    | TOKFROM strv
      {
	      $$ = $2;
      }

compress: TOKCOMPRESS
	  {
		  $$ = 1;
	  }
	| /* empty */
	  {
		  $$ = 0;
	  }

actitem: execpipe strv
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
	 {
		 struct deliver_remove_header_data *data;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_remove_header;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 data->hdrs = $1;
	 }
       | TOKADDHEADER strv val
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
       | imaptype server userpassnetrc folder1 verify nocrammd5 noplain nologin
	 starttls insecure oauthbearer xoauth2
	 {
		 struct deliver_imap_data	*data;

		 if ($1 && $9)
			 yyerror("use either imaps or set starttls");

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_imap;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

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

		 data->folder.str = $4;
		 data->server.ssl = $1;
		 data->server.verify = $5;
		 data->server.host = $2.host;
		 if ($2.port != NULL)
			 data->server.port = $2.port;
		 else if ($1)
			 data->server.port = xstrdup("imaps");
		 else
			 data->server.port = xstrdup("imap");
		 data->server.ai = NULL;
		 data->nocrammd5 = $6;
		 data->noplain = $7;
		 data->nologin = $8;
		 data->starttls = $9;
		 data->server.insecure = $10;
		 data->oauthbearer = $10;
		 data->xoauth2 = $11;
	 }
       | TOKSMTP server from to
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
		 data->from.str = $3;
		 data->to.str = $4;
	 }
       | TOKLMTP server from to
	 {
		 struct deliver_lmtp_data       *data;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_lmtp;

		 data = xcalloc(1, sizeof *data);
		 $$->data = data;

		 if (*$2.host == '/')
			data->socket = $2.host;
		 else {
			data->server.host = $2.host;
			if ($2.port != NULL)
				data->server.port = $2.port;
			else
				data->server.port = xstrdup("24");
		 }
		 data->from.str = $3;
		 data->to.str = $4;
	 }
       | TOKSTDOUT
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->deliver = &deliver_stdout;
	 }
       | TOKTAG strv optval
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

actlist: actlist actitem
	 {
		 $$ = $1;

		 TAILQ_INSERT_TAIL($$, $2, entry);
		 $2->idx = parse_actionidx++;
	 }
       | actitem
	 {
		 $$ = xmalloc(sizeof *$$);
		 TAILQ_INIT($$);

		 TAILQ_INSERT_HEAD($$, $1, entry);
		 $1->idx = 0;

		 parse_actionidx = 1;
	 }

defaction: TOKACTION replstrv users actitem
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

		   t->users = $3;
		   TAILQ_INSERT_TAIL(&conf.actions, t, entry);

		   print_action(t);

		   xfree($2);
	   }
	 | TOKACTION replstrv users '{' actlist '}'
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

		   t->users = $3;
		   TAILQ_INSERT_TAIL(&conf.actions, t, entry);

		   print_action(t);

		   xfree($2);
	   }

accounts: accountp strv
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
	  {
		  $$ = $3;
	  }

actions: actionp strv
	 {
		 if (*$2 == '\0')
			 yyerror("invalid action name");

		 $$ = xmalloc(sizeof *$$);
		 ARRAY_INIT($$);
		 ARRAY_EXPAND($$, 1);
		 ARRAY_LAST($$).str = $2;
	 }
       | actionp '{' replstrslist '}'
	 {
		 $$ = $3;
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

retre: casere
       {
	       $$ = $1;
       }
     | /* empty */
       {
	       $$.str = NULL;
       }

ltgt: '<'
     {
	     $$ = CMP_LT;
     }
   | '>'
     {
	     $$ = CMP_GT;
     }

eqne: TOKEQ
      {
	      $$ = CMP_EQ;
      }
    | TOKNE
      {
	      $$ = CMP_NE;
      }

cmp: ltgt
     {
	     $$ = $1;
     }
   | eqne
     {
	     $$ = $1;
     }

execpipe: TOKEXEC
	  {
		  $$ = 0;
	  }
	| TOKPIPE
	  {
		  $$ = 1;
	  }

writeappend: TOKWRITE
	     {
		     $$ = 0;
	     }
	   | TOKAPPEND
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

expritem: not TOKALL
	  {
		  $$ = xcalloc(1, sizeof *$$);
		  $$->match = &match_all;
		  $$->inverted = $1;
	  }
	| not casere area
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

		  data->user.str = $4;
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
	| not TOKAGE ltgt time
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

perform: users actionp actitem cont
	 {
		 struct action	*t;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = parse_ruleidx++;
		 $$->actions = NULL;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = !$4;
		 $$->users = $1;

		 t = $$->lambda = xcalloc(1, sizeof *$$->lambda);
		 xsnprintf(t->name, sizeof t->name, "<rule %u>", $$->idx);
		 t->users = NULL;
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
	 {
		 struct action	*t;

		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = parse_ruleidx++;
		 $$->actions = NULL;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = !$6;
		 $$->users = $1;

		 t = $$->lambda = xcalloc(1, sizeof *$$->lambda);
		 xsnprintf(t->name, sizeof t->name, "<rule %u>", $$->idx);
		 t->users = NULL;
		 t->list = $4;

		 if (parse_rule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&parse_rule->rules, $$, entry);
	 }
       | users actions cont
	 {
		 $$ = xcalloc(1, sizeof *$$);
		 $$->idx = parse_ruleidx++;
		 $$->lambda = NULL;
		 $$->actions = $2;
		 TAILQ_INIT(&$$->rules);
		 $$->stop = !$3;
		 $$->users = $1;

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

		 if (parse_rule == NULL)
			 TAILQ_INSERT_TAIL(&conf.rules, $$, entry);
		 else
			 TAILQ_INSERT_TAIL(&parse_rule->rules, $$, entry);

		 ARRAY_ADD(&parse_rulestack, parse_rule);
		 parse_rule = $$;
	 }

close: '}'
       {
	       if (parse_rule == NULL)
		       yyerror("missing {");

	       parse_rule = ARRAY_LAST(&parse_rulestack);
	       ARRAY_TRUNC(&parse_rulestack, 1);
       }

rule: TOKMATCH expr perform
      {
	      $3->expr = $2;
	      print_rule($3);
      }

folderlist: /* empty */
	    {
		    $$ = xmalloc(sizeof *$$);
		    ARRAY_INIT($$);
		    ARRAY_ADD($$, xstrdup("INBOX"));
	    }
	  | folders
	    {
		    $$ = $1;
	    }

folder1: /* empty */
	 {
		 $$ = xstrdup("INBOX");
	 }
       | folderp strv
	 {
		 $$ = $2;
	 }


groups: groupp replstrv
	{
		if (*$2 == '\0')
			yyerror("invalid group");

		$$ = xmalloc(sizeof *$$);
		ARRAY_INIT($$);
		ARRAY_ADD($$, $2);
	}
      | groupp '{' stringslist '}'
	{
		$$ = $3;
	}

nocrammd5: TOKNOCRAMMD5
	   {
		   $$ = 1;
	   }
	 | /* empty */
	   {
		   $$ = 0;
	   }

noplain: TOKNOPLAIN
	 {
		 $$ = 1;
	 }
       | /* empty */
	 {
		 $$ = 0;
	 }

nologin: TOKNOLOGIN
	 {
		 $$ = 1;
	 }
       | /* empty */
	 {
		 $$ = 0;
	 }

starttls: TOKSTARTTLS
	  {
		  $$ = 1;
	  }
	| /* empty */
	  {
		  $$ = 0;
	  }


uidl: TOKNOUIDL
      {
	      $$ = 0;
      }
    | /* empty */
      {
	      $$ = 1;
      }

insecure: TOKINSECURE
	  {
		  $$ = 1;
	  }
	| /* empty */
	  {
		  $$ = 0;
	  }

oauthbearer: TOKOAUTHBEARER
	     {
		     $$ = 1;
	     }
	   | /* empty */
	     {
		     $$ = 0;
	     }

xoauth2: TOKXOAUTH2
	 {
		 $$ = 1;
	 }
       | /* empty */
	 {
		 $$ = 0;
	 }

verify: TOKNOVERIFY
	{
		$$ = 0;
	}
      | /* empty */
	{
		$$ = 1;
	}

apop: TOKNOAPOP
      {
	      $$ = 0;
      }
    | /* empty */
      {
	      $$ = 1;
      }

only: TOKNEWONLY
      {
	      $$ = FETCH_ONLY_NEW;
      }
    | TOKOLDONLY
      {
	      $$ = FETCH_ONLY_OLD;
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

nntptype: TOKNNTP
	  {
		  $$ = 0;
	  }
	| TOKNNTPS
	  {
		  $$ = 1;
	  }

userpassnetrc: TOKUSER replstrv TOKPASS replstrv
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
	       {
		       if (*$2 == '\0')
			       yyerror("invalid user");

		       $$.user = $2;
		       $$.user_netrc = 0;
		       $$.pass = NULL;
		       $$.pass_netrc = 1;
	       }
	     | TOKPASS replstrv
	       {
		       if (*$2 == '\0')
			       yyerror("invalid pass");

		       $$.user = NULL;
		       $$.user_netrc = 1;
		       $$.pass = $2;
		       $$.pass_netrc = 0;
	       }

userpassreqd: TOKUSER replstrv TOKPASS replstrv
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

userpass: userpassreqd
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

poponly: only TOKCACHE replpathv
	 {
		 $$.path = $3;
		 $$.only = $1;
	 }
       | /* empty */
	 {
		 $$.path = NULL;
		 $$.only = FETCH_ONLY_ALL;
	 }

imaponly: only
	  {
		  $$ = $1;
	  }
	| /* empty */
	  {
		  $$ = FETCH_ONLY_ALL;
	  }

fetchtype: poptype server userpassnetrc poponly apop verify uidl starttls
	   insecure
	   {
		   struct fetch_pop3_data	*data;

		   if ($1 && $8)
			   yyerror("use either pop3s or set starttls");

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
		   data->uidl = $7;
		   data->starttls = $8;
		   data->server.insecure = $9;

		   data->path = $4.path;
		   data->only = $4.only;
	   }
	 | TOKPOP3 TOKPIPE replstrv userpassreqd poponly apop
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
	 | imaptype server userpassnetrc folderlist imaponly verify nocrammd5
	   noplain nologin starttls insecure oauthbearer xoauth2
	   {
		   struct fetch_imap_data	*data;

		   if ($1 && $10)
			   yyerror("use either imaps or set starttls");

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

		   data->folders = $4;
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
		   data->nocrammd5 = $7;
		   data->noplain = $8;
		   data->nologin = $9;
		   data->starttls = $10;
		   data->server.insecure = $11;
		   data->oauthbearer = $12;
		   data->xoauth2 = $13;
	   }
	 | TOKIMAP TOKPIPE replstrv userpass folderlist imaponly
	   {
		   struct fetch_imap_data	*data;

		   $$.fetch = &fetch_imappipe;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->user = $4.user;
		   data->pass = $4.pass;
		   data->folders = $5;
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
	   {
		   struct fetch_maildir_data	*data;

		   $$.fetch = &fetch_maildir;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->maildirs = $1;
	   }
	 | mboxes
	   {
		   struct fetch_mbox_data	*data;

		   $$.fetch = &fetch_mbox;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;
		   data->mboxes = $1;
	   }
	 | nntptype server userpassnetrc groups TOKCACHE replpathv verify
	   insecure
	   {
		   struct fetch_nntp_data	*data;
		   char				*cause;

		   if (*$6 == '\0')
			   yyerror("invalid cache");

		   $$.fetch = &fetch_nntp;
		   data = xcalloc(1, sizeof *data);
		   $$.data = data;

		   if ($3.user_netrc && $3.pass_netrc) {
			   if (find_netrc1($2.host,
			       &data->user, &data->pass, &cause) != 0) {
				   log_debug2("%s", cause);
				   xfree(cause);
				   data->user = NULL;
				   data->pass = NULL;
			   }

		   } else {
			   if ($3.user_netrc)
				   find_netrc($2.host, &data->user, NULL);
			   else
				   data->user = $3.user;
			   if ($3.pass_netrc)
				   find_netrc($2.host, NULL, &data->pass);
			   else
				   data->pass = $3.pass;
		   }

		   data->names = $4;
		   data->path = $6;
		   if (data->path == NULL || *data->path == '\0')
			   yyerror("invalid cache");

		   data->server.ssl = $1;
		   data->server.verify = $7;
		   data->server.insecure = $8;
		   data->server.host = $2.host;
		   if ($2.port != NULL)
			   data->server.port = $2.port;
		   else if ($1)
			   data->server.port = xstrdup("nntps");
		   else
			   data->server.port = xstrdup("nntp");
		   data->server.ai = NULL;
	   }

account: TOKACCOUNT replstrv disabled users fetchtype keep
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
		 a->users = $4;
		 a->fetch = $5.fetch;
		 a->data = $5.data;
		 TAILQ_INSERT_TAIL(&conf.accounts, a, entry);

		 if (a->users != NULL)
			 su = fmt_replstrs(" users=", a->users);
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
