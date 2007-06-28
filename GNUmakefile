# $Id$

.PHONY: clean

PROG= fdm
VERSION= 1.3
DATE= $(shell date +%Y%m%d-%H%M)

PREFIX?= /usr/local

BIN_OWNER= bin
BIN_GROUP= root

CC= gcc

ifeq ($(shell uname),SunOS)
YACC= yacc
YFLAGS= -d
else
YACC= bison
YFLAGS= -dy
endif

LEX= flex
LFLAGS= -l

INSTALLBIN= install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 555
INSTALLMAN= install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 444

SRCS= fdm.c \
      attach.c buffer.c cleanup.c command.c connect.c io.c log.c netrc.c \
      child-deliver.c child-fetch.c child.c \
      pcre.c re.c privsep.c replace.c shm-mmap.c strb.c db-tdb.c \
      xmalloc-debug.c  xmalloc.c \
      deliver-add-header.c deliver-append.c deliver-drop.c deliver-exec.c \
      deliver-keep.c deliver-maildir.c deliver-mbox.c deliver-pipe.c \
      deliver-remove-header.c deliver-rewrite.c deliver-smtp.c \
      deliver-stdout.c deliver-tag.c deliver-to-cache.c deliver-write.c \
      fetch-imap.c fetch-imappipe.c fetch-maildir.c fetch-nntp.c fetch-pop3.c \
      fetch-stdin.c imap-common.c \
      mail-callback.c mail-state.c mail-time.c  mail.c \
      match-age.c match-attachment.c match-command.c match-in-cache.c \
      match-matched.c match-regexp.c match-size.c match-string.c \
      match-tagged.c  match-unmatched.c \
      parent-deliver.c parent-fetch.c \
      y.tab.c lex.yy.c

DEFS= -DBUILD="\"$(VERSION) ($(DATE))\""

ifeq ($(shell uname),Darwin)
INCDIRS+= -I/usr/local/include/openssl -Icompat
SRCS+= compat/strtonum.c compat/vis.c
DEFS+= -DNO_STRTONUM -DNO_SETRESUID -DNO_SETRESGID -DNO_SETPROCTITLE
endif

ifeq ($(shell uname),Linux)
INCDIRS+= -I/usr/include/openssl -Icompat
SRCS+= compat/strlcpy.c compat/strlcat.c compat/strtonum.c compat/vis.c
DEFS+= $(shell getconf LFS_CFLAGS) -D_GNU_SOURCE \
        -DNO_STRLCPY -DNO_STRLCAT -DNO_SETPROCTITLE -DNO_STRTONUM -DNO_QUEUE_H
# Required for LLONG_MAX and friends
CFLAGS+= -std=c99
endif

OBJS= $(patsubst %.c,%.o,$(SRCS))
CPPFLAGS+= $(DEFS) -I. -I- $(INCDIRS)
CFLAGS+= -g -ggdb -DDEBUG
#CFLAGS+= -pedantic -std=c99
#CFLAGS+= -Wredundant-decls  -Wdisabled-optimization -Wendif-label
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+= -Wundef -Wshadow -Wbad-function-cast -Winline -Wcast-align

ifdef DB
DEFS+= -DDB
LIBS+= -ltdb
endif
ifdef PCRE
DEFS+= -DPCRE
LIBS+= -lpcre
endif

LIBS+= -lssl -lz

CLEANFILES= $(PROG) y.tab.c lex.yy.c y.tab.h $(OBJS) .depend

all: fdm

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $+

depend: $(SRCS)
	$(CC) $(CPPFLAGS) -MM $(SRCS) > .depend

y.tab.c y.tab.h: parse.y
	$(YACC) $(YFLAGS) $<

lex.yy.c: lex.l
	$(LEX) $(LFLAGS) $<

install:
	$(INSTALLBIN) $(PROG) $(DESTDIR)$(PREFIX)/bin/$(PROG)
	$(INSTALLMAN) $(PROG).1 $(DESTDIR)$(PREFIX)/man/man1/$(PROG).1
	$(INSTALLMAN) $(PROG).conf.5 $(DESTDIR)$(PREFIX)/man/man5/$(PROG).conf.5

clean:
	rm -f $(CLEANFILES)

ifeq ($(wildcard .depend),.depend)
include .depend
endif
