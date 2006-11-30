# $Id$

DEBUG= 0

TESTS= account.test macros.test options.test

all:		regress

TARGETS= 
.for n in ${TESTS}
TARGETS+= ${n}
${n}::
		@echo ${n}:
		@awk -v CMD="../fdm -vvnf /dev/stdin" -v DEBUG=${DEBUG} \
			-f test.awk ${n}
.endfor

.PHONY: regress ${TARGETS}

regress:	${TARGETS}
