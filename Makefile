# $Id$

.SUFFIXES: .c .o .y .h
.PHONY: clean lint regress yannotate manual \
	update-index.html upload-index.html

PROG= fdm
VERSION= 1.3

OS!= uname
REL!= uname -r
DATE!= date +%Y%m%d-%H%M

SRCS= fdm.c \
      attach.c buffer.c cleanup.c command.c connect.c io.c log.c netrc.c \
      child-deliver.c child-fetch.c child.c \
      pcre.c re.c privsep.c replace.c shm-mmap.c strb.c db-tdb.c \
      xmalloc-debug.c xmalloc.c \
      deliver-add-header.c deliver-append.c deliver-drop.c deliver-exec.c \
      deliver-keep.c deliver-maildir.c deliver-mbox.c deliver-pipe.c \
      deliver-remove-header.c deliver-rewrite.c deliver-smtp.c \
      deliver-stdout.c deliver-tag.c deliver-to-cache.c deliver-write.c \
      fetch-imap.c fetch-imappipe.c fetch-maildir.c fetch-nntp.c fetch-pop3.c \
      fetch-stdin.c imap-common.c \
      mail-callback.c mail-state.c mail-time.c mail.c file.c \
      match-age.c match-attachment.c match-command.c match-in-cache.c \
      match-matched.c match-regexp.c match-size.c match-string.c \
      match-tagged.c match-unmatched.c \
      parent-deliver.c parent-fetch.c \
      parse.y parse-fn.c lex.c
HDRS= fdm.h array.h fetch.h match.h deliver.h

YACC= yacc -d

CC?= cc
INCDIRS+= -I. -I- -I/usr/local/include
CFLAGS+= -DBUILD="\"$(VERSION) ($(DATE))\""
.ifdef PROFILE
# Don't use ccache
CC= /usr/bin/gcc
CFLAGS+= -pg -DPROFILE -fprofile-arcs -ftest-coverage -O0
.endif
CFLAGS+= -g -ggdb -DDEBUG
#CFLAGS+= -pedantic -std=c99
#CFLAGS+= -Wredundant-decls  -Wdisabled-optimization -Wendif-labels
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+= -Wundef -Wshadow -Wbad-function-cast -Winline -Wcast-align

.ifdef DB
CFLAGS+= -DDB
LIBS+= -ltdb
.endif
.ifdef PCRE
CFLAGS+= -DPCRE
LIBS+= -lpcre
.endif

# OS X
.if ${OS} == "Darwin"
SRCS+= compat/strtonum.c
INCDIRS+= -Icompat -I/usr/local/include/openssl
CFLAGS+= -DNO_STRTONUM -DNO_SETRESUID -DNO_SETRESGID -DNO_SETPROCTITLE
.endif

# NetBSD
.if ${OS} == "NetBSD"
SRCS+= compat/strtonum.c
INCDIRS+= -Icompat
CFLAGS+= -DNO_STRTONUM -DNO_SETRESUID -DNO_SETRESGID
.endif

# FreeBSD
.if ${OS} == "FreeBSD"
INCDIRS+= -Icompat -I/usr/local/include/openssl

# FreeBSD 5
.if ${REL:R} == 5
SRCS+= compat/strtonum.c
CFLAGS+= -DNO_STRTONUM
.endif
.endif

PREFIX?= /usr/local
INSTALLBIN= install -g bin -o root -m 555
INSTALLMAN= install -g bin -o root -m 444

LDFLAGS+= -L/usr/local/lib
.ifdef PROFILE
LDFLAGS+= -pg
.endif
LIBS+= -lssl -lcrypto -lz

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/}

DISTFILES= *.[chyl] Makefile GNUmakefile *.[1-9] fdm-sanitize \
	   README MANUAL TODO CHANGES \
	   `find examples regress compat -type f -and ! -path '*CVS*'`

CLEANFILES= ${PROG} *.o compat/*.o y.tab.c y.tab.h .depend \
	    ${PROG}-*.tar.gz *~ */*~ *.ln ${PROG}.core MANUAL index.html

.c.o:
		${CC} ${CFLAGS} ${INCDIRS} -c ${.IMPSRC} -o ${.TARGET}

.y.o:
		${YACC} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c y.tab.c -o ${.TARGET}

all:		${PROG}

${PROG}:	${OBJS}
		${CC} ${LDFLAGS} -o ${PROG} ${LIBS} ${OBJS}

dist:		clean manual
		grep '^#CFLAGS.*-DDEBUG' Makefile
		grep '^#CFLAGS.*-DDEBUG' GNUmakefile
		tar -zc \
			-s '/.*/${PROG}-${VERSION}\/\0/' \
			-f ${PROG}-${VERSION}.tar.gz ${DISTFILES}

lint:
		lint -cehvx ${CFLAGS:M-D*} ${SRCS:M*.c}

depend:
		mkdep ${CFLAGS} ${INCDIRS} ${SRCS:M*.c}

regress:	${PROG}
		cd regress && ${MAKE}

yannotate:
		awk -f yannotate.awk parse.y > parse.y.new
		mv parse.y.new parse.y
		trim parse.y

upload-index.html:
		scp index.html nicm@shell.sf.net:index.html
		ssh nicm@shell.sf.net sh update-index-fdm.sh

update-index.html: manual
		nroff -mdoc fdm.conf.5|m2h -u > fdm.conf.5.html
		nroff -mdoc fdm.1|m2h -u > fdm.1.html
		awk -v V=${VERSION} -f makeindex.awk index.html.in > index.html
		rm -f fdm.conf.5.html fdm.1.html

manual:
		awk -f makemanual.awk MANUAL.in > MANUAL

install:	all
		${INSTALLBIN} ${PROG} ${DESTDIR}${PREFIX}/bin/${PROG}
		${INSTALLMAN} ${PROG}.1 ${DESTDIR}${PREFIX}/man/man1/
		${INSTALLMAN} ${PROG}.conf.5 ${DESTDIR}${PREFIX}/man/man5/

uninstall:
		rm -f ${DESTDIR}${PREFIX}/bin/${PROG}
		rm -f ${DESTDIR}${PREFIX}/man/man1/${PROG}.1
		rm -f ${DESTDIR}${PREFIX}/man/man5/${PROG}.conf.5

clean:
		rm -f ${CLEANFILES}
