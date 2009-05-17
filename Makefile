# $Id$

.SUFFIXES: .c .o
.PHONY: clean regress

VERSION= 1.7

FDEBUG= 1

CC?= cc
YACC= yacc -d
CFLAGS+= -DBUILD="\"$(VERSION)\""
LDFLAGS+= -L/usr/local/lib
LIBS+= -lssl -lcrypto -ltdb -lz

# This sort of sucks but gets rid of the stupid warning and should work on
# most platforms...
CCV!= (${CC} -v 2>&1|awk '/gcc version 4/') || true
.if empty(CCV)
CPPFLAGS:= -I. -I- -I/usr/local/include ${CPPFLAGS}
.else
CPPFLAGS:= -iquote. -I/usr/local/include ${CPPFLAGS}
.endif

.ifdef FDEBUG
LDFLAGS+= -Wl,-E
CFLAGS+= -g -ggdb -DDEBUG
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wsign-compare
CFLAGS+= -Wundef -Wbad-function-cast -Winline -Wcast-align
.endif

.ifdef COURIER
CFLAGS+= -DLOOKUP_COURIER
LIBS+= -lcourierauth
.endif

.ifdef PCRE
CFLAGS+= -DPCRE
LIBS+= -lpcre
.endif

PREFIX?= /usr/local
INSTALLDIR= install -d
INSTALLBIN= install -g bin -o root -m 555
INSTALLMAN= install -g bin -o root -m 444

SRCS!= echo *.c|sed 's|y.tab.c||g'; echo y.tab.c
.include "config.mk"
OBJS= ${SRCS:S/.c/.o/}

.c.o:
		${CC} ${CPPFLAGS} ${CFLAGS} -c ${.IMPSRC} -o ${.TARGET}

all:		fdm

lex.o:		y.tab.c

y.tab.c:	parse.y
		${YACC} parse.y

fdm:		${OBJS}
		${CC} ${LDFLAGS} -o fdm ${OBJS} ${LIBS}

depend:
		mkdep ${CPPFLAGS} ${CFLAGS} ${SRCS:M*.c}

clean:
		rm -f fdm *.o .depend *~ *.core *.log compat/*.o y.tab.[ch]

clean-all:	clean
		rm -f config.h config.mk

regress:	fdm
		cd regress && ${MAKE}

install:	all
		${INSTALLDIR} ${DESTDIR}${PREFIX}/bin
		${INSTALLBIN} fdm ${DESTDIR}${PREFIX}/bin/
		${INSTALLDIR} ${DESTDIR}${PREFIX}/man/man1
		${INSTALLMAN} fdm.1 ${DESTDIR}${PREFIX}/man/man1/
		${INSTALLDIR} ${DESTDIR}${PREFIX}/man/man5
		${INSTALLMAN} fdm.conf.5 ${DESTDIR}${PREFIX}/man/man5/

uninstall:
		rm -f ${DESTDIR}${PREFIX}/bin/fdm
		rm -f ${DESTDIR}${PREFIX}/man/man1/fdm.1
		rm -f ${DESTDIR}${PREFIX}/man/man5/fdm.conf.5
