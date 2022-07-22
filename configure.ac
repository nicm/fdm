# $Id$

AC_INIT(fdm, 2.1)
RELEASE=2.1
AC_SUBST(RELEASE)

AC_CONFIG_AUX_DIR(etc)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CANONICAL_HOST

: ${CFLAGS=""}

CPPFLAGS="$CPPFLAGS -I/usr/local/include"
LDFLAGS="$LDFLAGS -L/usr/local/lib"

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_YACC

test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc
test "$localstatedir" = '${prefix}/var' && localstatedir=/var

AC_ARG_ENABLE(
	debug,
	AC_HELP_STRING(--enable-debug, create a debug build),
	found_debug=$enable_debug
)
AM_CONDITIONAL(IS_DEBUG, test "x$found_debug" = xyes)

AC_ARG_ENABLE(
	static,
	AC_HELP_STRING(--enable-static, create a static build),
	found_static=$enable_static
)
if test "x$found_static" = xyes; then
	LDFLAGS="$LDFLAGS -static"
fi

AC_ARG_ENABLE(
	pcre2,
	AC_HELP_STRING(--enable-pcre2, use PCRE2),
	found_pcre2=$enable_pcre2
)
if test "x$found_pcre2" = xyes; then
	CPPFLAGS="$CPPFLAGS -DPCRE2"

	AC_SEARCH_LIBS(
		pcre2_compile_8,
		[pcre2-8],
		found_pcre=yes,
		found_pcre=no
	)
	if test "x$found_pcre" = xno; then
		AC_MSG_ERROR("libpcre2 not found")
	fi
fi

AC_CHECK_HEADERS(
	[ \
		sys/queue.h \
		sys/tree.h \
	]
)
AC_CHECK_FUNCS(
	[ \
		setproctitle \
		setresuid \
		setresgid \
	]
)
AC_CHECK_DECL(
	MREMAP_MAYMOVE,
	AC_CHECK_FUNC([mremap]),
	,
	[
		#define _GNU_SOURCE
		#include <sys/mman.h>
	]
)

AC_SEARCH_LIBS(
	tdb_open,
	[tdb],
	found_libtdb=yes,
	found_libtdb=no
)
if test "x$found_libtdb" = xno; then
	AC_MSG_ERROR("libtdb not found")
fi

AC_SEARCH_LIBS(
	gzflush,
	[z],
	found_libz=yes,
	found_libz=no
)
if test "x$found_libz" = xno; then
	AC_MSG_ERROR("libz not found")
fi

AC_SEARCH_LIBS(
	BIO_new,
	[crypto],
	found_libcrypto=yes,
	found_libcrypto=no
)
if test "x$found_libcrypto" = xno; then
	AC_MSG_ERROR("libcrypto not found")
fi
AC_SEARCH_LIBS(
	OPENSSL_init_ssl,
	[ssl],
	found_libssl=yes,
	found_libssl=no
)
AC_SEARCH_LIBS(
	SSL_library_init,
	[ssl],
	found_libssl=yes
)
if test "x$found_libssl" = xno; then
	AC_MSG_ERROR("libssl not found")
fi

AC_CHECK_DECL(strlcpy, found_strlcpy=yes, found_strlcpy=no)
if test "x$found_strlcpy" = xyes; then
	AC_DEFINE(HAVE_STRLCPY)
fi
AM_CONDITIONAL(NO_STRLCPY, [test "x$found_strlcpy" = xno])

AC_CHECK_DECL(strlcat, found_strlcat=yes, found_strlcat=no)
if test "x$found_strlcat" = xyes; then
	AC_DEFINE(HAVE_STRLCAT)
fi
AM_CONDITIONAL(NO_STRLCAT, [test "x$found_strlcat" = xno])

AC_CHECK_FUNC(strtonum, found_strtonum=yes, found_strtonum=no)
if test "x$found_strtonum" = xyes; then
	AC_DEFINE(HAVE_STRTONUM)
fi
AM_CONDITIONAL(NO_STRTONUM, [test "x$found_strtonum" = xno])

AC_MSG_CHECKING(for b64_ntop)
AC_TRY_LINK(
	[
		#include <sys/types.h>
		#include <netinet/in.h>
		#include <resolv.h>
	],
	[b64_ntop(NULL, 0, NULL, 0);],
	found_b64_ntop=yes,
	found_b64_ntop=no
)
if test "x$found_b64_ntop" = xno; then
	AC_MSG_RESULT(no)

	AC_MSG_CHECKING(for b64_ntop with -lresolv)
	LIBS="$LIBS -lresolv"
	AC_TRY_LINK(
		[
			#include <sys/types.h>
			#include <netinet/in.h>
			#include <resolv.h>
		],
		[b64_ntop(NULL, 0, NULL, 0);],
		found_b64_ntop=yes,
		found_b64_ntop=no
	)
	if test "x$found_b64_ntop" = xno; then
		AC_MSG_RESULT(no)
	fi
fi
if test "x$found_b64_ntop" = xyes; then
	AC_DEFINE(HAVE_B64_NTOP)
	AC_MSG_RESULT(yes)
fi
AM_CONDITIONAL(NO_B64_NTOP, [test "x$found_b64_ntop" = xno])

AC_OUTPUT(Makefile)
