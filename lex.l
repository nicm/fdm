/* -*-C-*- */

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

%option yylineno

%{
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fdm.h"
#include "y.tab.h"

extern int 			 yylex(void);
extern __dead printflike1 void	 yyerror(const char *, ...);

char 				*read_str(char);

/* Use a one-byte buffer so flushing it on include doesn't do any harm. */
#define YY_READ_BUF_SIZE 1

%}

%%

[0-9]+ {
	const char	*errstr;

        yylval.number = strtonum(yytext, 0, LLONG_MAX, &errstr);
	if (errstr != NULL)
		yyerror("number is %s", errstr);

        return (NUMBER);
}
[0-9]+[BbKkMmGg] {
	const char	*errstr;
        char		ch, *cp;

	cp = yytext + strlen(yytext) - 1;
	ch = *cp;
	*cp = '\0';

        yylval.number = strtonum(yytext, 0, LLONG_MAX, &errstr);
	if (errstr != NULL)
		yyerror("size is %s", errstr);

        switch (ch) {
        case 'k':
	case 'K':
		if (yylval.number > LLONG_MAX / 1024)
			yyerror("size is too large");
                yylval.number *= 1024;
                break;
        case 'm':
	case 'M':
		if (yylval.number > LLONG_MAX / (1024 * 1024))
			yyerror("size is too large");
                yylval.number *= 1024 * 1024;
                break;
        case 'g':
	case 'G':
		if (yylval.number > LLONG_MAX / (1024 * 1024 * 1024))
			yyerror("size is too large");
                yylval.number *= 1024 * 1024 * 1024;
                break;
        }

        return (SIZE);
}
\" {
	yylval.string = read_str('"');
        return (STRING);
}
\` {
	yylval.string = read_str('`');
        return (COMMAND);
}
\$[A-Za-z][A-Za-z0-9_]* {
        yylval.string = xstrdup(yytext);
	return (STRMACRO);
}
\$\{[A-Za-z][A-Za-z0-9_]*\} {
        yylval.string = xstrdup(yytext);
	return (STRMACROB);
}
\%[A-Za-z][A-Za-z0-9_]* {
        yylval.string = xstrdup(yytext);
	return (NUMMACRO);
}
\%\{[A-Za-z][A-Za-z0-9_]*\} {
        yylval.string = xstrdup(yytext);
	return (NUMMACROB);
}
(default-user|defuser) return (TOKDEFUSER);
(delete-oversized|deltoobig) return (TOKDELTOOBIG);
(lock-types|locktypes) return (TOKLOCKTYPES);
(maximum-size|maxsize) return (TOKMAXSIZE);
account	return (TOKACCOUNT);
accounts return (TOKACCOUNTS);
action return (TOKACTION);
actions return (TOKACTIONS);
all return (TOKALL);
allow-multiple return (TOKALLOWMANY);
and return (TOKAND);
append return (TOKAPPEND);
body return (TOKBODY);
case return (TOKCASE);
continue return (TOKCONTINUE);
disabled return (TOKDISABLED);
domain return (TOKDOMAIN);
domains return (TOKDOMAINS);
dotlock return (LCKDOTLOCK);
drop return (TOKDROP);
exec return (TOKEXEC);
fcntl return (LCKFCNTL);
flock return (LCKFLOCK);
folder return (TOKFOLDER);
from-headers return (TOKFROMHEADERS);
header return (TOKHEADER);
headers return (TOKHEADERS);
imap return (TOKIMAP);
imaps return (TOKIMAPS);
in return (TOKIN);
include return (TOKINCLUDE);
lock-file return (TOKLOCKFILE);
maildir return (TOKMAILDIR);
match return (TOKMATCH);
matched return (TOKMATCHED);
mbox return (TOKMBOX);
none return (TOKNONE);
not return (TOKNOT);
or return (TOKOR);
pass return (TOKPASS);
pipe return (TOKPIPE);
pop3 return (TOKPOP3);
pop3s return (TOKPOP3S);
port return (TOKPORT);
proxy return (TOKPROXY);
returns return (TOKRETURNS);
rewrite return (TOKREWRITE);
server return (TOKSERVER);
set return (TOKSET);
size return (TOKSIZE);
smtp return (TOKSMTP);
stdin return (TOKSTDIN);
string return (TOKSTRING);
tag return (TOKTAG);
tagged return (TOKTAGGED);
to return (TOKTO);
unmatched return (TOKUNMATCHED);
user return (TOKUSER);
users return (TOKUSERS);
write return (TOKWRITE);
\{ return ('{');
\} return ('}');
\( return ('(');
\) return (')');
\, return (',');
\< return ('<');
\> return ('>');
== return (TOKEQ);
!= return (TOKNE);
= return ('=');
\#.*\n /* ignore comments */;
\n /* ignore end of line */;
[ \t]+ /* ignore whitespace */;

%%

char *
read_str(char endc)
{
	int		 done = 0, ch, valid;
	size_t		 pos = 0, len, off, slen;
	char	         name[MAXNAMESIZE], *s, *buf;
	struct macro	*macro;

	len = 24;
        buf = xmalloc(len + 1);

        while (!done) {
                switch (ch = input()) {
		case 0:
		case EOF:
			yyerror("unterminated string");
                case '\\':
                        switch (ch = input()) {
			case 0:
			case EOF:
				yyerror("unterminated string");
                        case 'r':
                                ch = '\r';
                                break;
                        case 'n':
                                ch = '\n';
                                break;
                        case 't':
                                ch = '\t';
                                break;
                        }
                        break;
		case '$':
		case '%':
			name[0] = ch;
			off = 1;

			/* first character */
			ch = input();
			if (ch == 0 || ch == EOF)
				yyerror("unterminated string");
			if (ch != '{') {
				unput(ch);
				ch = name[0];
				break;
			}
			
			/* remaining characters */
			valid = 1;
			do {
				ch = input();
				if (ch == 0 || ch == EOF)
					yyerror("unterminated string");
				if (ch == '}')
					break;
				if (!ismacro(ch))
					valid = 0;
				name[off++] = ch;
			} while (off < (sizeof name));
			if (ch != '}')
				yyerror("missing } or macro name too long");
			name[off] = '\0';
			if (!valid || !ismacrofirst(name[1]))
				yyerror("invalid macro name: %s", name);

			if ((macro = find_macro(name)) == NULL)
				yyerror("undefined macro: %s", name);
			
			if (macro->type == MACRO_NUMBER)
 				xasprintf(&s, "%lld", macro->value.number);
			else
				s = macro->value.string;
			slen = strlen(s);

			ENSURE_FOR(buf, len, pos, slen + 1);
			memcpy(buf + pos, s, slen);
			pos += slen;

			if (macro->type == MACRO_NUMBER)
				xfree(s);
			continue;
                }
		if (ch == endc) {
                        done = 1;
                        continue;
		}

                buf[pos] = ch;
                pos++;
                ENSURE_SIZE(buf, len, pos);
        }

        buf[pos] = '\0';

	return (buf);
}
