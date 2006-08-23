# $Id$

.SUFFIXES: .c .o .y .l .h
.PHONY: clean index.html

PROG= fdm
VERSION= 0.1

OS!= uname
REL!= uname -r
DATE!= date +%Y%m%d-%H%M

SRCS= fdm.c log.c xmalloc.c parse.y lex.l io.c replace.c connect.c mail.c \
      fetch-pop3.c fetch-pop3s.c fetch-stdin.c deliver-smtp.c deliver-pipe.c \
      deliver-drop.c deliver-maildir.c deliver-mbox.c deliver-write.c \
      deliver-append.c

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/:S/.l/.o/}

LEX= lex
YACC= yacc -d

CC= cc
CFLAGS+= -g -ggdb -std=c99
CFLAGS+= -pg
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
LDFLAGS+= -pg
LIBS= -lcrypto -lssl

TARFLAGS= 
DISTFILES= *.[chyl] Makefile ${PROG}.conf *.[1-9] README

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

index.html:
		nroff -mdoc fdm.conf.5|m2h -u > fdm.conf.5.html
		nroff -mdoc fdm.1|m2h -u > fdm.1.html
		awk ' \
			{ if ($$0 ~ /%%/) {			\
				name = substr($$0, 3);		\
				while ((getline < name) == 1) {	\
					print $$0;		\
				}				\
				close(name);			\
			} else {				\
				print $$0;			\
			} }' index.html.in > index.html
		rm -f fdm.conf.5.html fdm.1.html

install:	all
		${INSTALLBIN} ${PROG} ${PREFIX}/bin/${PROG}
		${INSTALLMAN} ${PROG}.1 ${PREFIX}/man/man1/
		${INSTALLMAN} ${PROG}.conf.5 ${PREFIX}/man/man5/

uninstall:
		rm -f ${PREFIX}/sbin/${PROG}
		rm -f ${PREFIX}/man/man1/${PROG}.1
		rm -f ${PREFIX}/man/man5/${PROG}.conf.5

clean:
		rm -f ${CLEANFILES}
