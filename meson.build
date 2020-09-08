project(
        'fdm',
        'c',
        version: '2.0',
        license: 'ISC',
        default_options: [
                'c_std=gnu99',
                'optimization=2'
        ],
	meson_version: '>=0.49.0',
)

cc   = meson.get_compiler('c')
conf = configuration_data()

add_project_arguments(
        [
                '-D_GNU_SOURCE',
                '-DVERSION="@0@"'.format(meson.project_version()),
                '-DSYSCONFFILE="@0@/fdm.conf"'.format(get_option('sysconfdir')),
                '-DSYSLOCKFILE="@0@/run/fdm.lock"'.format(get_option('localstatedir')),
        ],
        language: 'c',
)

if get_option('debug')
        add_project_arguments(
                '-DDEBUG',
                cc.get_supported_arguments(
                        '-Wno-long-long', '-W', '-Wnested-externs',
                        '-Wformat=2', '-Wmissing-prototypes',
                        '-Wstrict-prototypes', '-Wmissing-declarations',
                        '-Wwrite-strings', '-Wshadow', '-Wpointer-arith',
                        '-Wsign-compare', '-Wundef', '-Wbad-function-cast',
                        '-Winline', '-Wcast-align',
                        '-Wdeclaration-after-statement', '-Wno-pointer-sign',
                ),
            language: 'c',
        )
endif

yacc = find_program('yacc')

if get_option('static')
        add_project_arguments('-static', language: 'c')
endif

libs = [
        dependency('tdb'),
        dependency('zlib'),
        dependency('openssl'),
]
if get_option('pcre')
        libs += dependency('libpcre')
        add_project_arguments('-DPCRE', language: 'c')
endif

compats = []
if cc.has_header('sys/queue.h')
        add_project_arguments('-DHAVE_QUEUE_H', language: 'c')
endif
if cc.has_header('sys/tree.h')
        add_project_arguments('-DHAVE_TREE_H', language: 'c')
endif
if cc.has_header_symbol('stdlib.h', 'setproctitle')
        add_project_arguments('-DHAVE_SETPROCTITLE', language: 'c')
endif
if cc.has_header_symbol('unistd.h', 'setresuid', args: '-D_GNU_SOURCE')
        add_project_arguments('-DHAVE_SETRESUID', language: 'c')
endif
if cc.has_header_symbol('unistd.h', 'setresgid', args: '-D_GNU_SOURCE')
        add_project_arguments('-DHAVE_SETRESGID', language: 'c')
endif
if cc.has_header_symbol('sys/mman.h', 'MREMAP_MAYMOVE', args: '-D_GNU_SOURCE')
        add_project_arguments('-DHAVE_MREMAP', language: 'c')
endif
if cc.has_header_symbol('string.h', 'strlcat')
        add_project_arguments('-DHAVE_STRLCAT', language: 'c')
else
        compats += 'compat/strlcat.c'
endif
if cc.has_header_symbol('string.h', 'strlcpy')
        add_project_arguments('-DHAVE_STRLCPY', language: 'c')
else
        compats += 'compat/strlcpy.c'
endif
if cc.has_header_symbol('stdlib.h', 'strtonum')
        add_project_arguments('-DHAVE_STRTONUM', language: 'c')
else
        compats += 'compat/strtonum.c'
endif
ntop_test = '''
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>

int
main(void)
{
        b64_ntop(NULL, 0, NULL, 0);

        return 0;
}
'''
if cc.links(ntop_test)
        add_project_arguments('-DHAVE_B64_NTOP', language: 'c')
else
        resolv = cc.find_library('resolv')
        if cc.links(ntop_test, dependencies: resolv)
                add_project_arguments('-DHAVE_B64_NTOP', language: 'c')
                libs += resolv
        else
                compats += 'compat/base64.c'
        endif
endif

ygen = generator(
        yacc,
        output: ['@BASENAME@.c', '@BASENAME@.h'],
        arguments: ['-d', '-o', '@OUTPUT0@', '@INPUT@']
)
parse = ygen.process('parse.y')

sources = [
        'attach.c',
        'buffer.c',
        'cache-op.c',
        'child-deliver.c',
        'child-fetch.c',
        'child.c',
        'cleanup.c',
        'command.c',
        'connect.c',
        'db-tdb.c',
        'deliver-add-header.c',
        'deliver-add-to-cache.c',
        'deliver-drop.c',
        'deliver-imap.c',
        'deliver-keep.c',
        'deliver-maildir.c',
        'deliver-mbox.c',
        'deliver-pipe.c',
        'deliver-remove-from-cache.c',
        'deliver-remove-header.c',
        'deliver-rewrite.c',
        'deliver-smtp.c',
        'deliver-stdout.c',
        'deliver-tag.c',
        'deliver-write.c',
        'fdm.c',
        'fetch-imap.c',
        'fetch-imappipe.c',
        'fetch-maildir.c',
        'fetch-mbox.c',
        'fetch-nntp.c',
        'fetch-pop3.c',
        'fetch-pop3pipe.c',
        'fetch-stdin.c',
        'fetch.h',
        'file.c',
        'imap-common.c',
        'io.c',
        'io.h',
        'lex.c',
        'log.c',
        'lookup-passwd.c',
        'lookup.c',
        'mail-state.c',
        'mail-time.c',
        'mail.c',
        'match-account.c',
        'match-age.c',
        'match-all.c',
        'match-attachment.c',
        'match-command.c',
        'match-in-cache.c',
        'match-matched.c',
        'match-regexp.c',
        'match-size.c',
        'match-string.c',
        'match-tagged.c',
        'match-unmatched.c',
        'match.h',
        'netrc.c',
        'parent-deliver.c',
        'parent-fetch.c',
        'parse-fn.c',
        'pcre.c',
        'pop3-common.c',
        'privsep.c',
        're.c',
        'replace.c',
        'shm-mmap.c',
        'strb.c',
        'timer.c',
        'xmalloc.c',
]

fdm = executable(
        'fdm',
        sources, compats, parse,
        dependencies: libs,
        install: true
)

install_man(
	'fdm.1',
	'fdm.conf.5'
)
