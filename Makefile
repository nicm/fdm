# $Id$

.SUFFIXES: .c .o .y .l .h
.PHONY: clean lint regress yannotate manual \
	update-index.html upload-index.html

PROG= fdm
VERSION= 1.1

OS!= uname
REL!= uname -r
DATE!= date +%Y%m%d-%H%M

SRCS= fdm.c log.c xmalloc.c xmalloc-debug.c io.c replace.c connect.c mail.c \
      command.c fetch-pop3.c fetch-imap.c fetch-stdin.c fetch-nntp.c \
      fetch-maildir.c re.c deliver-smtp.c deliver-pipe.c deliver-drop.c \
      deliver-keep.c deliver-maildir.c deliver-mbox.c deliver-write.c \
      deliver-append.c deliver-rewrite.c match-regexp.c match-command.c \
      match-tagged.c match-size.c match-string.c match-matched.c match-age.c \
      match-unmatched.c match-attachment.c child.c privsep.c attach.c \
      cleanup.c imap-common.c fetch-imappipe.c deliver-remove-header.c \
      deliver-stdout.c deliver-append-string.c strb.c deliver-add-header.c \
      deliver-exec.c child-fetch.c parent-fetch.c child-deliver.c \
      parent-deliver.c mail-state.c netrc.c shm-mmap.c shm-sysv.c \
      parse.y lex.l

LEX= lex
YACC= yacc -d

CC= cc
INCDIRS+= -I. -I- -I/usr/local/include
CFLAGS+= -DBUILD="\"$(VERSION) ($(DATE))\""
.ifdef PROFILE
CFLAGS+= -pg -DPROFILE
.endif
CFLAGS+= -g -ggdb -DDEBUG
#CFLAGS+= -pedantic -std=c99
#CFLAGS+= -Wredundant-decls  -Wdisabled-optimization -Wendif-labels
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+= -Wundef -Wshadow -Wbad-function-cast -Winline -Wcast-align

.ifdef SHM_SYSV
CFLAGS+= -DSHM_SYSV
.else
CFLAGS+= -DSHM_MMAP
.endif

# OS X
.if ${OS} == "Darwin"
SRCS+= compat/strtonum.c compat/vis.c
INCDIRS+= -Icompat -I/usr/local/include/openssl
CFLAGS+= -DNO_STRTONUM -DNO_SETRESUID -DNO_SETRESGID -DNO_SETPROCTITLE
.endif

# NetBSD
.if ${OS} == "NetBSD"
SRCS+= compat/strtonum.c compat/vis.c
INCDIRS+= -Icompat
CFLAGS+= -DNO_STRTONUM -DNO_SETRESUID -DNO_SETRESGID
.endif

# FreeBSD
.if ${OS} == "FreeBSD"
SRCS+= compat/vis.c
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
LIBS= -lssl -lcrypto -lz

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/:S/.l/.o/}

DISTFILES= *.[chyl] Makefile GNUmakefile *.[1-9] fdm-sanitize \
	   README MANUAL TODO CHANGES \
	   `find examples regress compat -type f -and ! -path '*CVS*'`

CLEANFILES= ${PROG} *.o compat/*.o y.tab.c lex.yy.c y.tab.h .depend \
	    ${PROG}-*.tar.gz *~ *.ln ${PROG}.core MANUAL index.html

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

dist:		clean manual
		grep '^#CFLAGS.*-DDEBUG' Makefile
		grep '^#CFLAGS.*-DDEBUG' GNUmakefile
		tar -zxc \
			-s '/.*/${PROG}-${VERSION}\/\0/' \
			-f ${PROG}-${VERSION}.tar.gz ${DISTFILES}

lint:
		lint -cehvx ${CFLAGS:M-D*} ${SRCS:M*.c}

depend:
		mkdep ${CFLAGS} ${SRCS:M*.c}

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
		awk -f makeindex.awk index.html.in > index.html
		rm -f fdm.conf.5.html fdm.1.html

manual:
		awk -f makemanual.awk MANUAL.in > MANUAL

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
