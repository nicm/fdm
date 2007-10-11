# $Id$

CLEANFILES= *~

TESTFILES!= echo *.test

TARGETS=
.for n in ${TESTFILES}
TARGETS+= ${n}
${n}:
		@echo ${n}:
		@HOME=. awk -v CMD="../fdm -vvvnf /dev/stdin" \
			-v DEBUG=${DEBUG} -f test.awk ${n}
.endfor

.MAIN:		all
.PHONY: 	regress clean ${TARGETS}
.PRECIOUS: 	${TARGETS}

all:		regress

regress:	${TARGETS}
		cd tests && ${MAKE}
		cd test-pop3 && ${MAKE}
		cd test-imap && ${MAKE}

clean:
		rm -f ${CLEANFILES}
