# $Id$

bin_PROGRAMS = fdm
CLEANFILES = parse.c parse.h

EXTRA_DIST = \
	CHANGES README MANUAL \
	examples compat/*.[ch] fdm-sanitize \
	array.h \
	deliver.h \
	fdm.h \
	fetch.h \
	io.h \
	match.h
dist-hook:
	make clean

CPPFLAGS += \
	-DSYSCONFFILE="\"$(sysconfdir)/fdm.conf\"" \
	-DSYSLOCKFILE="\"$(localstatedir)/run/fdm.lock\""
CFLAGS += -D_GNU_SOURCE -std=gnu99 -O2
if IS_DEBUG
CFLAGS += -g
CFLAGS += -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS += -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS += -Wwrite-strings -Wshadow -Wpointer-arith -Wsign-compare
CFLAGS += -Wundef -Wbad-function-cast -Winline -Wcast-align
CFLAGS += -Wdeclaration-after-statement -Wno-pointer-sign
CPPFLAGS += -DDEBUG
endif
YFLAGS += -d

dist_man1_MANS = fdm.1
dist_man5_MANS = fdm.conf.5

dist_fdm_SOURCES = \
	attach.c \
	buffer.c \
	cache-op.c \
	child-deliver.c \
	child-fetch.c \
	child.c \
	cleanup.c \
	command.c \
	connect.c \
	db-tdb.c \
	deliver-add-header.c \
	deliver-add-to-cache.c \
	deliver-drop.c \
	deliver-imap.c \
	deliver-keep.c \
	deliver-maildir.c \
	deliver-mbox.c \
	deliver-pipe.c \
	deliver-remove-from-cache.c \
	deliver-remove-header.c \
	deliver-rewrite.c \
	deliver-smtp.c \
	deliver-stdout.c \
	deliver-tag.c \
	deliver-write.c \
	fdm.c \
	fetch-imap.c \
	fetch-imappipe.c \
	fetch-maildir.c \
	fetch-mbox.c \
	fetch-nntp.c \
	fetch-pop3.c \
	fetch-pop3pipe.c \
	fetch-stdin.c \
	fetch.h \
	file.c \
	imap-common.c \
	io.c \
	io.h \
	log.c \
	lookup-passwd.c \
	lookup.c \
	mail-state.c \
	mail-time.c \
	mail.c \
	match-account.c \
	match-age.c \
	match-all.c \
	match-attachment.c \
	match-command.c \
	match-in-cache.c \
	match-matched.c \
	match-regexp.c \
	match-size.c \
	match-string.c \
	match-tagged.c \
	match-unmatched.c \
	match.h \
	netrc.c \
	parent-deliver.c \
	parent-fetch.c \
	parse-fn.c \
	pcre.c \
	pop3-common.c \
	privsep.c \
	re.c \
	replace.c \
	shm-mmap.c \
	strb.c \
	timer.c \
	xmalloc-debug.c \
	xmalloc.c \
	\
	parse.y \
	lex.c

nodist_fdm_SOURCES =
if NO_STRLCAT
nodist_fdm_SOURCES += compat/strlcat.c
endif
if NO_STRLCPY
nodist_fdm_SOURCES += compat/strlcpy.c
endif
if NO_STRTONUM
nodist_fdm_SOURCES += compat/strtonum.c
endif
