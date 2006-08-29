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

extern int 			yylex(void);
extern __dead printflike1 void	yyerror(const char *, ...);
%}

%%

[0-9]+ {
	long long	num;

	errno = 0;
        num = strtoll(yytext, NULL, 10);
	if (num == 0 && (errno == EINVAL || errno == ERANGE))
		yyerror("illegal number");
	yylval.number = num;

        return (NUMBER);
}
[0-9]+[BbKkMmGg] {
        char		ch;
	long long	num;

        ch = *(yytext + strlen(yytext) - 1);
        *(yytext + strlen(yytext) - 1) = '\0';

	errno = 0;
	num = strtoll(yytext, NULL, 10);
	if (num == 0 && (errno == EINVAL || errno == ERANGE))
		yyerror("illegal size");
	yylval.number = num;

        switch (ch) {
        case 'k':
	case 'K':
		if (yylval.number > LLONG_MAX / 1024)
			yyerror("size too large");
                yylval.number *= 1024;
                break;
        case 'm':
	case 'M':
		if (yylval.number > LLONG_MAX / (1024 * 1024))
			yyerror("size too large");
                yylval.number *= 1024 * 1024;
                break;
        case 'g':
	case 'G':
		if (yylval.number > LLONG_MAX / (1024 * 1024 * 1024))
			yyerror("size too large");
                yylval.number *= 1024 * 1024 * 1024;
                break;
        }

        return (SIZE);
}
\" {
	int		done = 0, ch;
	size_t		pos = 0, len = 24;

        yylval.string = xmalloc(len + 1);

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
                case '"':
                        done = 1;
                        continue;
                }

                *(yylval.string + pos) = ch;
                pos++;
                ENSURE_SIZE(yylval.string, len, pos);
        }

        *(yylval.string + pos) = '\0';

        return (STRING);
}
account	return (TOKACCOUNT);
accounts return (TOKACCOUNTS);
action return (TOKACTION);
actions return (TOKACTIONS);
all return (TOKALL);
and return (TOKAND);
append return (ACTAPPEND);
body return (TOKBODY);
case return (TOKCASE);
command return (TOKCOMMAND);
continue return (TOKCONTINUE);
defuser return (TOKDEFUSER);
deltoobig return (TOKDELTOOBIG);
disabled return (TOKDISABLED);
domain return (TOKDOMAIN);
domains return (TOKDOMAINS);
dotlock return (LCKDOTLOCK);
drop return (ACTDROP);
fcntl return (LCKFCNTL);
flock return (LCKFLOCK);
from-headers return (TOKFROMHEADERS);
folder return (TOKFOLDER);
header return (TOKHEADER);
headers return (TOKHEADERS);
imap return (TOKIMAP);
imaps return (TOKIMAPS);
in return (TOKIN);
locktypes return (TOKLOCKTYPES);
maildir return (ACTMAILDIR);
match return (TOKMATCH);
maxsize return (TOKMAXSIZE);
mbox return (ACTMBOX);
none return (TOKNONE);
not return (TOKNOT);
or return (TOKOR);
pass return (TOKPASS);
pipe return (ACTPIPE);
pop3 return (TOKPOP3);
pop3s return (TOKPOP3S);
port return (TOKPORT);
rewrite return (ACTREWRITE);
server return (TOKSERVER);
set return (TOKSET);
smtp return (ACTSMTP);
stdin return (TOKSTDIN);
to return (TOKTO);
unmatched return (TOKUNMATCHED);
matched return (TOKMATCHED);
user return (TOKUSER);
users return (TOKUSERS);
write return (ACTWRITE);
\{ return (SYMOPEN);
\} return (SYMCLOSE);
\#.*\n /* ignore comments */;
\n /* ignore end of line */;
[ \t]+ /* ignore whitespace */;

%%
