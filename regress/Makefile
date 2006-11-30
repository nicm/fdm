# $Id$

DEBUG= 0

TESTS= account.test macros.test

TARGETS= 
.for n in ${TESTS}
TARGETS+= ${n}
${n}::
		@echo ${n}:
		@awk -v CMD="../fdm -vvnf /dev/stdin" -v DEBUG=${DEBUG} \
			-f test.awk ${n}
.endfor

.PHONY: regress ${TARGETS}

all:		regress

regress:	${TARGETS}
