# $Id$

.PHONY: clean

VERSION= 1.7

FDEBUG= 1

CC?= gcc
YACC= yacc -d
CPPFLAGS+= -I/usr/local/include -I.
CFLAGS+= -DBUILD="\"$(VERSION)\""
LDFLAGS+= -L/usr/local/lib
LIBS+= -lssl -lcrypto -ltdb -lz

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
BINDIR?= $(PREFIX)/bin
MANDIR?= $(PREFIX)/man
INSTALLDIR= install -d
INSTALLBIN= install -m 755
INSTALLMAN= install -m 644

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
		$(INSTALLDIR) $(DESTDIR)$(BINDIR)
		$(INSTALLBIN) fdm $(DESTDIR)$(BINDIR)
		$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man1
		$(INSTALLMAN) fdm.1 $(DESTDIR)$(MANDIR)/man1
		$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man5
		$(INSTALLMAN) fdm.conf.5 $(DESTDIR)$(MANDIR)/man5
