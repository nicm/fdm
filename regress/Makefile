# $Id$

DEBUG= 0

CLEANFILES= *~

TESTFILES= account.test macros.test options.test proxy.test

TARGETS= 
.for n in ${TESTFILES}
TARGETS+= ${n}
${n}:
		@echo ${n}:
		@awk -v CMD="../fdm -vvnf /dev/stdin" -v DEBUG=${DEBUG} \
			-f test.awk ${n}
.endfor

.MAIN:		all
.PHONY: 	regress clean ${TARGETS}
.PRECIOUS: 	${TARGETS}

all:		regress

regress:	${TARGETS}

clean:
		rm -f ${CLEANFILES}
