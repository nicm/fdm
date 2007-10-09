# $Id$

.SUFFIXES: .c .o .y .h
.PHONY: clean lint regress yannotate manual \
	update-index.html upload-index.html

PROG= fdm
VERSION= 1.5

OS!= uname
REL!= uname -r
DATE!= date +%Y%m%d-%H%M

# This must be empty as OpenBSD includes it in default CFLAGS.
DEBUG=

SRCS= fdm.c \
      attach.c buffer.c cleanup.c command.c connect.c io.c log.c netrc.c \
      child-deliver.c child-fetch.c child.c \
      pcre.c re.c privsep.c replace.c shm-mmap.c strb.c db-tdb.c \
      xmalloc-debug.c xmalloc.c timer.c \
      deliver-add-header.c deliver-drop.c deliver-keep.c deliver-maildir.c \
      deliver-mbox.c deliver-pipe.c deliver-remove-header.c deliver-rewrite.c \
      deliver-smtp.c deliver-stdout.c deliver-tag.c deliver-add-to-cache.c \
      deliver-remove-from-cache.c deliver-write.c \
      fetch-imap.c fetch-imappipe.c fetch-maildir.c fetch-nntp.c fetch-pop3.c \
      fetch-pop3pipe.c fetch-stdin.c fetch-mbox.c pop3-common.c imap-common.c \
      mail-state.c mail-time.c mail.c file.c cache-op.c \
      match-all.c match-age.c match-attachment.c match-command.c \
      match-in-cache.c match-matched.c match-regexp.c match-size.c \
      match-string.c match-tagged.c match-unmatched.c match-account.c \
      parent-deliver.c parent-fetch.c \
      parse.y parse-fn.c lex.c
HDRS= fdm.h array.h fetch.h match.h deliver.h

YACC= yacc -d

CC?= cc
INCDIRS+= -I. -I- -I/usr/local/include
.ifdef PROFILE
# Don't use ccache
CC= /usr/bin/gcc
CFLAGS+= -pg -DPROFILE -fprofile-arcs -ftest-coverage -O0
.endif
.ifdef DEBUG
CFLAGS+= -g -ggdb -DDEBUG
LDFLAGS+= -Wl,-E
CFLAGS+= -DBUILD="\"$(VERSION) ($(DATE))\""
.else
CFLAGS+= -DBUILD="\"$(VERSION)\""
.endif
#CFLAGS+= -pedantic -std=c99
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+= -Wundef -Wshadow -Wbad-function-cast -Winline -Wcast-align

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
INCDIRS+= -Icompat -I/usr/pkg/include
CFLAGS+= -DNO_STRTONUM -DNO_SETRESUID -DNO_SETRESGID
LDFLAGS+= -L/usr/pkg/lib
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
LIBS+= -lssl -lcrypto -ltdb -lz

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/}

DISTDIR= ${PROG}-${VERSION}
DISTFILES= *.[chyl] Makefile GNUmakefile *.[1-9] fdm-sanitize \
	   README MANUAL TODO CHANGES \
	   `find examples compat -type f -and ! -path '*CVS*'` \
	   `find examples regress -type f -and ! -path '*CVS*'`

CLEANFILES= ${PROG} *.o compat/*.o y.tab.c y.tab.h .depend \
	    ${DISTDIR}.tar.gz *~ */*~ *.ln ${PROG}.core MANUAL index.html

.c.o:
		${CC} ${CFLAGS} ${INCDIRS} -c ${.IMPSRC} -o ${.TARGET}

.y.o:
		${YACC} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c y.tab.c -o ${.TARGET}

all:		${PROG}

${PROG}:	${OBJS}
		${CC} ${LDFLAGS} -o ${PROG} ${LIBS} ${OBJS}

dist:		clean manual
		grep '^#DEBUG=' Makefile
		grep '^#DEBUG=' GNUmakefile
		[ "`(grep '^VERSION' Makefile; grep '^VERSION' GNUmakefile)| \
			uniq -u`" = "" ]
		tar -zc \
			-s '/.*/${DISTDIR}\/\0/' \
			-f ${DISTDIR}.tar.gz ${DISTFILES}

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
