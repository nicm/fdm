# $Id$

.PHONY: clean

PROG = fdm
VERSION = 0.1
DATE=$(shell date +%Y%m%d-%H%M)

## Installation parameters

PREFIX = /usr/local

BIN_OWNER = bin
BIN_GROUP = root

### Programs

CC = gcc

ifeq ($(shell uname),SunOS)
YACC = yacc
YFLAGS = -d
else
YACC = bison
YFLAGS = -dy
endif

LEX = flex
LFLAGS = -l

INSTALLBIN = install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 555
INSTALLMAN = install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 444

### Compilation

SRCS= fdm.c log.c xmalloc.c io.c replace.c connect.c mail.c \
      fetch-pop3.c fetch-pop3s.c fetch-stdin.c deliver-smtp.c deliver-pipe.c \
      deliver-drop.c deliver-maildir.c deliver-mbox.c \
      y.tab.c lex.yy.c

DEFS = $(shell getconf LFS_CFLAGS) -DBUILD="\"$(VERSION) ($(DATE))\""

ifeq ($(shell uname),Linux)
SRCS += strlcpy.c strlcat.c
DEFS += -D_GNU_SOURCE -DNO_STRLCPY -DNO_STRLCAT
endif

OBJS = $(patsubst %.c,%.o,$(SRCS))
CPPFLAGS = $(DEFS) -I.
CFLAGS = -std=c99 -pedantic -Wno-long-long -Wall -W -Wnested-externs \
	 -Wformat-security -Wmissing-prototypes -Wstrict-prototypes \
	 -Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual \
	 -Wsign-compare 

LIBS = -lssl

CLEANFILES = $(PROG) y.tab.c lex.yy.c y.tab.h $(OBJS) .depend

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

clean:
	rm -f $(CLEANFILES)

ifeq ($(wildcard .depend),.depend)
include .depend
endif
