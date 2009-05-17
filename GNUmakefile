# $Id$

.PHONY: clean

VERSION= 1.7

FDEBUG= 1

CC?= gcc
YACC= yacc -d
CFLAGS+= -DBUILD="\"$(VERSION)\""
LDFLAGS+= -L/usr/local/lib
LIBS+= -lssl -lcrypto -ltdb -lz

# This sort of sucks but gets rid of the stupid warning and should work on
# most platforms...
ifeq ($(shell ($(CC) -v 2>&1|awk '/gcc version 4/') || true), )
CPPFLAGS:= -I. -I- $(CPPFLAGS)
else
CPPFLAGS:= -iquote. $(CPPFLAGS)
endif

ifdef FDEBUG
LDFLAGS+= -rdynamic
CFLAGS+= -g -ggdb -DDEBUG
LIBS+= -ldl
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wsign-compare
CFLAGS+= -Wundef -Wbad-function-cast -Winline -Wcast-align
endif

ifdef COURIER
CFLAGS+= -DLOOKUP_COURIER
LIBS+= -lcourierauth
endif

ifdef PCRE
CFLAGS+= -DPCRE
LIBS+= -lpcre
endif

PREFIX?= /usr/local
INSTALLDIR= install -d
INSTALLBIN= install -g bin -o root -m 555
INSTALLMAN= install -g bin -o root -m 444

SRCS= $(shell echo *.c|sed 's|y.tab.c||g'; echo y.tab.c)
include config.mk
OBJS= $(patsubst %.c,%.o,$(SRCS))

all:		fdm

lex.o:		y.tab.c

y.tab.c:	parse.y
		$(YACC) $<

fdm:		$(OBJS)
		$(CC) $(LDFLAGS) -o fdm $+ $(LIBS)

depend: 	$(SRCS)
		$(CC) $(CPPFLAGS) -MM $(SRCS) > .depend

clean:
		rm -f fdm *.o .depend *~ *.core *.log compat/*.o y.tab.[ch]

clean-all:	clean
		rm -f config.h config.mk

install:	all
		$(INSTALLDIR) $(DESTDIR)$(PREFIX)/bin
		$(INSTALLBIN) fdm $(DESTDIR)$(PREFIX)/bin/fdm
		$(INSTALLDIR) $(DESTDIR)$(PREFIX)/man/man1
	 	$(INSTALLMAN) fdm.1 $(DESTDIR)$(PREFIX)/man/man1/fdm.1
		$(INSTALLDIR) $(DESTDIR)$(PREFIX)/man/man5
		$(INSTALLMAN) fdm.conf.5 $(DESTDIR)$(PREFIX)/man/man5/fdm.conf.5
