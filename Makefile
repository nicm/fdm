
# $Id$

.SUFFIXES: .c .o .y .l .h
.PHONY: clean update-index.html upload-index.html lint

PROG= fdm
VERSION= 0.6

OS!= uname
REL!= uname -r
DATE!= date +%Y%m%d-%H%M

SRCS= fdm.c log.c xmalloc.c parse.y lex.l io.c replace.c connect.c mail.c \
      fetch-pop3.c fetch-imap.c fetch-stdin.c deliver-smtp.c deliver-pipe.c \
      deliver-drop.c deliver-maildir.c deliver-mbox.c deliver-write.c \
      deliver-append.c deliver-rewrite.c deliver-tag.c \
      match-regexp.c match-command.c match-tag.c child.c parent.c privsep.c

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/:S/.l/.o/}

LEX= lex
YACC= yacc -dv

CC= cc
CFLAGS+= -std=c99
.ifdef PROFILE
CFLAGS+= -pg
.endif
CFLAGS+= -g -ggdb -DDEBUG
CFLAGS+= -pedantic -Wno-long-long
CFLAGS+= -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes
CFLAGS+= -Wmissing-declarations -Wwrite-strings
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare -Wredundant-decls
CFLAGS+= -DBUILD="\"$(VERSION) ($(DATE))\""

PREFIX?= /usr/local
INSTALLBIN= install -g bin -o root -m 555
INSTALLMAN= install -g bin -o root -m 444

INCDIRS= -I- -I. -I/usr/local/include
LDFLAGS+= -L/usr/local/lib
.ifdef PROFILE
LDFLAGS+= -pg
.endif
LIBS= -lcrypto -lssl

DISTFILES= *.[chyl] Makefile GNUmakefile ${PROG}.conf *.[1-9] README

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
		grep '^#CFLAGS.*-DDEBUG' Makefile
		tar -zxc \
			-s '/.*/${PROG}-${VERSION}\/\0/' \
			-f ${PROG}-${VERSION}.tar.gz ${DISTFILES}

lint:		
		lint -hx ${CFLAGS:M-D*} ${SRCS:M*.c}

depend:
		mkdep ${CFLAGS} ${SRCS}

port:
		tar -zxc \
			-s '/ports\/OpenBSD\/\(.*\)/${PROG}\/\1/' \
			-f ${PROG}-${VERSION}-openbsd-${REL}-port.tar.gz \
			ports/OpenBSD/Makefile ports/OpenBSD/distinfo \
			ports/OpenBSD/pkg/PLIST ports/OpenBSD/pkg/DESCR

upload-index.html:
		scp index.html nicm@shell.sf.net:index.html
		ssh nicm@shell.sf.net sh update-index-fdm.sh

update-index.html:
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
		rm -f ${PREFIX}/bin/${PROG}
		rm -f ${PREFIX}/man/man1/${PROG}.1
		rm -f ${PREFIX}/man/man5/${PROG}.conf.5

clean:
		rm -f ${CLEANFILES}
