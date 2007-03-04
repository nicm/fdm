# $Id$

.PHONY: clean

PROG= fdm
VERSION= 1.1
DATE= $(shell date +%Y%m%d-%H%M)

PREFIX= /usr/local

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

SRCS= fdm.c log.c xmalloc.c xmalloc-debug.c io.c replace.c connect.c mail.c \
      command.c shm.c fetch-pop3.c fetch-imap.c fetch-stdin.c fetch-nntp.c \
      fetch-maildir.c re.c deliver-smtp.c deliver-pipe.c deliver-drop.c \
      deliver-keep.c deliver-maildir.c deliver-mbox.c deliver-write.c \
      deliver-append.c deliver-rewrite.c match-regexp.c match-command.c \
      match-tagged.c match-size.c match-string.c match-matched.c match-age.c \
      match-unmatched.c match-attachment.c child.c parent.c privsep.c attach.c \
      cleanup.c imap-common.c fetch-imappipe.c deliver-remove-header.c \
      deliver-stdout.c deliver-append-string.c strb.c deliver-add-header.c \
      y.tab.c lex.yy.c

DEFS= -DBUILD="\"$(VERSION) ($(DATE))\""

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
#CFLAGS+= -g -ggdb -DDEBUG
#CFLAGS+= -pedantic -std=c99
#CFLAGS+= -Wredundant-decls  -Wdisabled-optimization -Wendif-label
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+= -Wundef -Wshadow -Wbad-function-cast -Winline -Wcast-align

LIBS+= -lssl -lz

CLEANFILES= $(PROG) y.tab.c lex.yy.c y.tab.h $(OBJS) .depend

all: fdm

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $+

depend: $(SRCS)
	$(CC) -MM $(SRCS) > .depend

y.tab.c y.tab.h: parse.y
	$(YACC) $(YFLAGS) $<

lex.yy.c: lex.l
	$(LEX) $(LFLAGS) $<

install:
	$(INSTALLBIN) $(PROG) $(PREFIX)/sbin/$(PROG)
	$(INSTALLMAN) $(PROG).1 $(PREFIX)/man/man1/$(PROG).1
	$(INSTALLMAN) $(PROG).conf.5 $(PREFIX)/man/man5/$(PROG).conf.5

clean:
	rm -f $(CLEANFILES)

ifeq ($(wildcard .depend),.depend)
include .depend
endif
