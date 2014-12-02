# $Id$

VERSION= 1.8

DISTDIR= fdm-${VERSION}
DISTFILES= *.[chl] Makefile GNUmakefile configure *.[1-9] fdm-sanitize \
	   README MANUAL TODO CHANGES \
	   `find examples compat regress -type f -and ! -path '*CVS*'`

dist:          	manual
		(./configure &&	make clean-all)
		grep '^#FDEBUG=' Makefile
		grep '^#FDEBUG=' GNUmakefile
		[ "`(grep '^VERSION' Makefile; grep '^VERSION' GNUmakefile)| \
		        uniq -u`" = "" ]
		chmod +x configure
		tar -zc \
		        -s '/.*/${DISTDIR}\/\0/' \
		        -f ${DISTDIR}.tar.gz ${DISTFILES}

manual:
		awk -f tools/makemanual.awk MANUAL.in > MANUAL

yannotate:
		awk -f tools/yannotate.awk parse.y > parse.y.new
		mv parse.y.new parse.y
		trim parse.y

upload-index.html: update-index.html
		scp index.html nicm,fdm@web.sf.net:/home/groups/f/fd/fdm/htdocs

update-index.html: manual
		mandoc -Thtml fdm.conf.5 > fdm.conf.5.html
		mandoc -Thtml fdm.1 > fdm.1.html
		awk -v V=${VERSION} -f tools/makeindex.awk \
			index.html.in > index.html
		rm -f fdm.conf.5.html fdm.1.html
