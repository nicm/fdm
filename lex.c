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

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"
#include "y.tab.h"

int	  lex_include;
u_int	  lex_ifdef;
int	  lex_skip;

int	  yylex(void);

int	  cmp_token(const void *, const void *);
int	  read_token(int);
long long read_number(int);
char	 *read_macro(int, int);
char	 *read_command(void);
char	 *read_string(char, int);
void	  include_start(char *);
int	  include_finish(void);

#define lex_getc() getc(parse_file->f)
#define lex_ungetc(ch) ungetc(ch, parse_file->f)

struct token {
	const char	*name;
	int		 value;
};
static const struct token tokens[] = {
	{ "B", TOKBYTES },
	{ "G", TOKGIGABYTES },
	{ "GB", TOKGIGABYTES },
	{ "K", TOKKILOBYTES },
	{ "KB", TOKKILOBYTES },
	{ "M", TOKMEGABYTES },
	{ "MB", TOKMEGABYTES },
	{ "account", TOKACCOUNT },
	{ "accounts", TOKACCOUNTS },
	{ "action", TOKACTION },
	{ "actions", TOKACTIONS },
	{ "add-header", TOKADDHEADER },
	{ "add-to-cache", TOKADDTOCACHE },
	{ "age", TOKAGE },
	{ "all", TOKALL },
	{ "allow-multiple", TOKALLOWMANY },
	{ "and", TOKAND },
	{ "any-name", TOKANYNAME },
	{ "any-size", TOKANYSIZE },
	{ "any-type", TOKANYTYPE },
	{ "append", TOKAPPEND },
	{ "attachment", TOKATTACHMENT },
	{ "b", TOKBYTES },
	{ "body", TOKBODY },
	{ "byte", TOKBYTES },
	{ "bytes", TOKBYTES },
	{ "cache", TOKCACHE },
	{ "case", TOKCASE },
	{ "command-user", TOKCMDUSER },
	{ "compress", TOKCOMPRESS },
	{ "continue", TOKCONTINUE },
	{ "count", TOKCOUNT },
	{ "courier", TOKCOURIER },
	{ "day", TOKDAYS },
	{ "days", TOKDAYS },
	{ "default-user", TOKDEFUSER },
	{ "delete-oversized", TOKDELTOOBIG },
	{ "disabled", TOKDISABLED },
	{ "domain", TOKDOMAIN },
	{ "dotlock", TOKDOTLOCK },
	{ "drop", TOKDROP },
	{ "exec", TOKEXEC },
	{ "expire", TOKEXPIRE },
	{ "fcntl", TOKFCNTL },
	{ "file-group", TOKFILEGROUP },
	{ "file-umask", TOKFILEUMASK },
	{ "flock", TOKFLOCK },
	{ "folder", TOKFOLDER },
	{ "folders", TOKFOLDERS },
	{ "from", TOKFROM },
	{ "g", TOKGIGABYTES },
	{ "gb", TOKGIGABYTES },
	{ "gigabyte", TOKGIGABYTES },
	{ "gigabytes", TOKGIGABYTES },
	{ "group", TOKGROUP },
	{ "groups", TOKGROUPS },
	{ "header", TOKHEADER },
	{ "headers", TOKHEADERS },
	{ "hour", TOKHOURS },
	{ "hours", TOKHOURS },
	{ "imap", TOKIMAP },
	{ "imaps", TOKIMAPS },
	{ "in", TOKIN },
	{ "in-cache", TOKINCACHE },
	{ "invalid", TOKINVALID },
	{ "k", TOKKILOBYTES },
	{ "kb", TOKKILOBYTES },
	{ "keep", TOKKEEP },
	{ "key", TOKKEY },
	{ "kilobyte", TOKKILOBYTES },
	{ "kilobytes", TOKKILOBYTES },
	{ "lock-file", TOKLOCKFILE },
	{ "lock-type", TOKLOCKTYPES },
	{ "lock-types", TOKLOCKTYPES },
	{ "lookup-order", TOKLOOKUPORDER },
	{ "m", TOKMEGABYTES },
	{ "maildir", TOKMAILDIR },
	{ "maildirs", TOKMAILDIRS },
	{ "match", TOKMATCH },
	{ "matched", TOKMATCHED },
	{ "maximum-size", TOKMAXSIZE },
	{ "mb", TOKMEGABYTES },
	{ "mbox", TOKMBOX },
	{ "mboxes", TOKMBOXES },
	{ "megabyte", TOKMEGABYTES },
	{ "megabytes", TOKMEGABYTES },
	{ "minute", TOKMINUTES },
	{ "minutes", TOKMINUTES },
	{ "month", TOKMONTHS },
	{ "months", TOKMONTHS },
	{ "new-only", TOKNEWONLY },
	{ "nntp", TOKNNTP },
	{ "nntps", TOKNNTPS },
	{ "no-apop", TOKNOAPOP },
	{ "no-cram-md5", TOKNOCRAMMD5 },
	{ "no-create", TOKNOCREATE },
	{ "no-login", TOKNOLOGIN },
	{ "no-received", TOKNORECEIVED },
	{ "no-verify", TOKNOVERIFY },
	{ "none", TOKNONE },
	{ "not", TOKNOT },
	{ "old-only", TOKOLDONLY },
	{ "or", TOKOR },
	{ "parallel-accounts", TOKPARALLELACCOUNTS },
	{ "pass", TOKPASS },
	{ "passwd", TOKPASSWD },
	{ "pipe", TOKPIPE },
	{ "pop3", TOKPOP3 },
	{ "pop3s", TOKPOP3S },
	{ "port", TOKPORT },
	{ "proxy", TOKPROXY },
	{ "purge-after", TOKPURGEAFTER },
	{ "queue-high", TOKQUEUEHIGH },
	{ "queue-low", TOKQUEUELOW },
	{ "remove-from-cache", TOKREMOVEFROMCACHE },
	{ "remove-header", TOKREMOVEHEADER },
	{ "remove-headers", TOKREMOVEHEADERS },
	{ "returns", TOKRETURNS },
	{ "rewrite", TOKREWRITE },
	{ "second", TOKSECONDS },
	{ "seconds", TOKSECONDS },
	{ "server", TOKSERVER },
	{ "set", TOKSET },
	{ "size", TOKSIZE },
	{ "smtp", TOKSMTP },
	{ "stdin", TOKSTDIN },
	{ "stdout", TOKSTDOUT },
	{ "string", TOKSTRING },
	{ "strip-characters", TOKSTRIPCHARACTERS },
	{ "tag", TOKTAG },
	{ "tagged", TOKTAGGED },
	{ "timeout", TOKTIMEOUT },
	{ "to", TOKTO },
	{ "to-cache", TOKADDTOCACHE },
	{ "total-size", TOKTOTALSIZE },
	{ "unmatched", TOKUNMATCHED },
	{ "unmatched-mail", TOKIMPLACT },
	{ "user", TOKUSER },
	{ "users", TOKUSERS },
	{ "value", TOKVALUE },
	{ "verify-certificates", TOKVERIFYCERTS },
	{ "week", TOKWEEKS },
	{ "weeks", TOKWEEKS },
	{ "write", TOKWRITE },
	{ "year", TOKYEARS },
	{ "years", TOKYEARS }
};

int
yylex(void)
{
	int	 	 ch, value;
	char		*path;
	struct replpath  rp;

	/* Switch to new file. See comment in read_token below. */
	if (lex_include) {
		while ((ch = lex_getc()) != EOF && isspace((u_char) ch))
			;

		if (ch != '"' && ch != '\'')
			yyerror("syntax error");
		if (ch == '"')
			rp.str = read_string('"', 1);
		else
			rp.str = read_string('\'', 0);
		path = replacepath(&rp, parse_tags, NULL, NULL, conf.user_home);
		xfree(rp.str);
		include_start(path);
		lex_include = 0;
	}

restart:
	while ((ch = lex_getc()) != EOF) {
		switch (ch) {
		case '#':
			/* Comment: discard until EOL. */
			while ((ch = lex_getc()) != '\n' && ch != EOF)
				;
			parse_file->line++;
			break;
		case '\'':
			yylval.string = read_string('\'', 0);
			value = STRING;
			goto out;
		case '"':
			yylval.string = read_string('"', 1);
			value = STRING;
			goto out;
		case '$':
			ch = lex_getc();
			if (ch == '(') {
				yylval.string = read_command();
				value = STRCOMMAND;
				goto out;
			}
			if (ch == '{' || isalnum((u_char) ch)) {
				yylval.string = read_macro('$', ch);
				value = STRMACRO;
				goto out;
			}
			yyerror("invalid macro name");
		case '%':
			ch = lex_getc();
			if (ch == '(') {
				yylval.string = read_command();
				value = NUMCOMMAND;
				goto out;
			}
			if (ch == '{' || isalnum((u_char) ch)) {
				yylval.string = read_macro('%', ch);
				value = NUMMACRO;
				goto out;
			}
			yyerror("invalid macro name");
		case '=':
			ch = lex_getc();
			if (ch == '=') {
				value = TOKEQ;
				goto out;
			}
			lex_ungetc(ch);
			value = '=';
			goto out;
		case '!':
			ch = lex_getc();
			if (ch == '=') {
				value = TOKNE;
				goto out;
			}
			lex_ungetc(ch);
			value = '!';
			goto out;
		case '~':
		case '+':
		case '(':
		case ')':
		case ',':
		case '<':
		case '>':
		case '{':
		case '}':
		case '*':
			value = ch;
			goto out;
		case '\n':
			parse_file->line++;
			break;
		case ' ':
		case '\t':
			break;
		default:
			if (ch != '_' && ch != '-' && !isalnum((u_char) ch))
				yyerror("unexpected character: %c", ch);

			if (isdigit((u_char) ch)) {
				yylval.number = read_number(ch);
				value = NUMBER;
				goto out;
			}

			value = read_token(ch);
			goto out;
		}
	}

	if (!include_finish())
		goto restart;
	if (lex_ifdef != 0)
		yyerror("missing endif");
	return (EOF);

out:
	if (lex_skip)
		goto restart;
	return (value);
}

int
cmp_token(const void *name, const void *ptr)
{
	const struct token	*token = ptr;

        return (strcmp(name, token->name));
}

int
read_token(int ch)
{
	int		 ch2;
	char		 token[128], *name;
	size_t		 tlen;
	struct token	*ptr;
	struct macro	*macro;

	tlen = 0;
	token[tlen++] = ch;
	while ((ch = lex_getc()) != EOF) {
		if (!isalnum((u_char) ch) && ch != '-' && ch != '_')
			break;
		token[tlen++] = ch;
		if (tlen == (sizeof token) - 1)
			yyerror("token too long");
	}
	token[tlen] = '\0';
	lex_ungetc(ch);

	/*
	 * ifdef/ifndef/endif is special-cased here since it is really really
	 * hard to make work with yacc.
	 */
	if (strcmp(token, "ifdef") == 0 || strcmp(token, "ifndef") == 0) {
		while ((ch = lex_getc()) != EOF && isspace((u_char) ch))
			;

		if (ch != '$' && ch != '%')
			yyerror("syntax error");
		ch2 = lex_getc();
		if (ch2 != '{' && !isalnum((u_char) ch2))
			yyerror("invalid macro name");

		name = read_macro(ch, ch2);
		macro = find_macro(name);
		xfree(name);

		if (token[2] == 'n' && macro != NULL)
			lex_skip = 1;
		if (token[2] != 'n' && macro == NULL)
			lex_skip = 1;
		lex_ifdef++;
		return (NONE);
	}
	if (strcmp(token, "endif") == 0) {
		if (lex_ifdef == 0)
			yyerror("spurious endif");
		lex_ifdef--;
		if (lex_ifdef == 0)
			lex_skip = 0;
		return (NONE);
	}

	if (strcmp(token, "include") == 0) {
		/*
		 * This is a bit strange.
		 *
		 * yacc may have symbols buffered and be waiting for more to
		 * decide which production to match, so we can't just switch
		 * file now. So, we set a flag that tells yylex to switch files
		 * next time it's called and return the NONE symbol. This is a
		 * placeholder not used in any real productions, so it should
		 * cause yacc to match using whatever it has (assuming it
		 * can). If we don't do this, there are problems with things
		 * like:
		 *
		 * 	$file = "abc"
		 * 	include "${file}"
		 *
		 * The include token is seen before yacc has matched the
		 * previous line, so the macro doesn't exist when we try to
		 * build the include file path.
		 */
		lex_include = 1;
		return (NONE);
	}

	ptr = bsearch(token, tokens,
	    (sizeof tokens)/(sizeof tokens[0]), sizeof tokens[0], cmp_token);
        if (ptr == NULL)
		yyerror("unknown token: %s", token);
	return (ptr->value);
}

long long
read_number(int ch)
{
	char		 number[32];
	size_t		 nlen;
	const char 	*errstr;
	long long	 n;

	nlen = 0;
	number[nlen++] = ch;
	while ((ch = lex_getc()) != EOF) {
		if (!isdigit((u_char) ch))
			break;
		number[nlen++] = ch;
		if (nlen == (sizeof number) - 1)
			yyerror("number too long");
	}
	number[nlen] = '\0';
	lex_ungetc(ch);

	n = strtonum(number, 0, LLONG_MAX, &errstr);
	if (errstr != NULL)
		yyerror("number is %s", errstr);
	return (n);
}

char *
read_macro(int type, int ch)
{
	char	name[MAXNAMESIZE];
	size_t	nlen;
	int	brackets;

	brackets = 0;
	if (ch == '{') {
		ch = lex_getc();
		if (!isalnum((u_char) ch))
			yyerror("invalid macro name");
		brackets = 1;
	}

	nlen = 0;
	name[nlen++] = type;
	name[nlen++] = ch;
	while ((ch = lex_getc()) != EOF) {
		if (!isalnum((u_char) ch) && ch != '-' && ch != '_')
			break;
		name[nlen++] = ch;
		if (nlen == (sizeof name) - 1)
			yyerror("macro name too long");
	}
 	name[nlen] = '\0';
	if (!brackets)
		lex_ungetc(ch);

	if (brackets && ch != '}')
		yyerror("missing }");
	if (*name == '\0')
		yyerror("empty macro name");

	return (xstrdup(name));
}

char *
read_command(void)
{
	int	 ch, nesting;
	size_t	 pos = 0, len, slen;
	char	*buf, *s;

	len = 24;
        buf = xmalloc(len + 1);

	nesting = 0;
        while ((ch = lex_getc()) != EOF) {
		switch (ch) {
		case '(':
			nesting++;
			break;
		case ')':
			if (nesting == 0) {
				buf[pos] = '\0';
				return (buf);
			}
			nesting--;
			break;
		case '"':
			s = read_string('"', 1);
			slen = strlen(s);
			ENSURE_SIZE(buf, len, pos + slen + 2);
			buf[pos++] = '"';
			memcpy(buf + pos, s, slen);
			pos += slen;
			buf[pos++] = '"';
			xfree(s);
			continue;
		case '\'':
			s = read_string('\'', 0);
			slen = strlen(s);
			ENSURE_SIZE(buf, len, pos + slen + 2);
			buf[pos++] = '\'';
			memcpy(buf + pos, s, slen);
			pos += slen;
			buf[pos++] = '\'';
			xfree(s);
			continue;
                }

                buf[pos++] = ch;
                ENSURE_SIZE(buf, len, pos);
        }

	yyerror("missing )");
}

char *
read_string(char endch, int esc)
{
	int		 ch, oldch;
	size_t		 pos, len, slen;
	char	        *name, *s, *buf;
	struct macro	*macro;

	len = 24;
        buf = xmalloc(len + 1);

	pos = 0;
        while ((ch = lex_getc()) != endch) {
                switch (ch) {
		case EOF:
			yyerror("missing %c", endch);
                case '\\':
			if (!esc)
				break;
                        switch (ch = lex_getc()) {
			case EOF:
				yyerror("missing %c", endch);
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
			if (!esc)
				break;
			oldch = ch;

			ch = lex_getc();
			if (ch == EOF)
				yyerror("missing %c", endch);
			if (ch != '{') {
				lex_ungetc(ch);
				ch = oldch;
				break;
			}

			name = read_macro(oldch, '{');
			if ((macro = find_macro(name)) == NULL) {
				xfree(name);
				continue;
			}
			xfree(name);

			if (macro->type == MACRO_NUMBER)
 				xasprintf(&s, "%lld", macro->value.num);
			else
				s = macro->value.str;
			slen = strlen(s);

			ENSURE_FOR(buf, len, pos, slen + 1);
			memcpy(buf + pos, s, slen);
			pos += slen;

			if (macro->type == MACRO_NUMBER)
				xfree(s);
			continue;
                }

                buf[pos++] = ch;
                ENSURE_SIZE(buf, len, pos);
        }

        buf[pos] = '\0';

	return (buf);
}

void
include_start(char *file)
{
	char		*path;
	FILE		*f;
	struct stat	 sb;

	if (*file == '\0')
		yyerror("invalid include file");

	if ((f = fopen(file, "r")) == NULL) {
		xasprintf(&path, "%s/%s", xdirname(conf.conf_file), file);
		if ((f = fopen(path, "r")) == NULL)
			yyerror("%s: %s", path, strerror(errno));
		xfree(file);
	} else
		path = file;

	if (fstat(fileno(f), &sb) != 0)
		yyerror("%s: %s", path, strerror(errno));
	if (geteuid() != 0 && (sb.st_mode & (S_IROTH|S_IWOTH)) != 0)
		log_warnx("%s: world readable or writable", path);

	ARRAY_ADD(&parse_filestack, parse_file);
	parse_file = xmalloc(sizeof *parse_file);
	parse_file->f = f;
	parse_file->line = 1;
	parse_file->path = path;

	log_debug2("including file %s", parse_file->path);
}

int
include_finish(void)
{
	if (ARRAY_EMPTY(&parse_filestack))
		return (1);
	log_debug2("finished file %s", parse_file->path);

	xfree(parse_file);
	parse_file = ARRAY_LAST(&parse_filestack);
	ARRAY_TRUNC(&parse_filestack, 1);

	return (0);
}
