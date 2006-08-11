# $Id$

.SUFFIXES: .c .o .y .l .h
.PHONY: clean

PROG= fdm
VERSION= 0.1

OS!= uname
REL!= uname -r
DATE!= date +%Y%m%d-%H%M

SRCS= fdm.c log.c xmalloc.c parse.y lex.l io.c replace.c connect.c
SRCS+= fetch-pop3.c fetch-pop3s.c fetch-stdin.c
SRCS+= deliver-smtp.c deliver-pipe.c deliver-drop.c deliver-maildir.c

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/:S/.l/.o/}

LEX= lex
YACC= yacc -d

CC= cc
CFLAGS+= -g -ggdb -std=c99
CFLAGS+= -DDEBUG
CFLAGS+= -pedantic -Wno-long-long
CFLAGS+= -Wall -W -Wnested-externs -Wformat-security
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare -Wredundant-decls
CFLAGS+= -DBUILD="\"$(VERSION) ($(DATE))\""

PREFIX?= /usr/local
INSTALLBIN= install -g bin -o root -m 555
INSTALLMAN= install -g bin -o root -m 444

INCDIRS= -I- -I. -I/usr/local/include
LDFLAGS+= -L/usr/local/lib
LIBS= -lm -lcrypto -lssl

TARFLAGS= 
DISTFILES= *.[chyl] Makefile ${PROG}.conf.sample # XXX *.[1-9] README

CLEANFILES= ${PROG} *.o y.tab.c lex.yy.c y.tab.h .depend ${PROG}-*.tar.gz \
	*.[1-9].gz *~ *.ln ${PROG}.core

.c.o:
		${CC} ${CFLAGS} ${INCDIRS} -c ${.IMPSRC} -o ${.TARGET}

.l.o:
		${LEX} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c lex.yy.c -o ${.TARGET}

.y.o:
		${YACC} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c y.tab.c -o ${.TARGET}

all:		${PROG}

${PROG}:	${OBJS}
		${CC} ${LDFLAGS} -o ${PROG} ${LIBS} ${OBJS}

dist:		clean
		tar -zxc \
			-s '/.*/${PROG}-${VERSION}\/\0/' \
			-f ${PROG}-${VERSION}.tar.gz ${DISTFILES}

depend:
		mkdep ${CFLAGS} ${SRCS}


install:	all
		${INSTALLBIN} ${PROG} ${PREFIX}/bin/${PROG}

uninstall:
		rm -f ${PREFIX}/sbin/${PROG}

clean:
		rm -f ${CLEANFILES}
