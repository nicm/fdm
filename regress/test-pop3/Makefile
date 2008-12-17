# $Id$

CLEANFILES= *~ *.fifo.{in,out} *.log *.conf

TESTFILES!= echo pop3-*.test

TARGETS=
.for n in ${TESTFILES}
TARGETS+= ${n}
${n}:
		@HOME=. FDM="../../fdm -h" sh test-pop3.sh ${n}
.endfor

.MAIN:		all
.PHONY: 	regress clean ${TARGETS}
.PRECIOUS: 	${TARGETS}

all:		regress

regress:	${TARGETS}

clean:
		rm -f ${CLEANFILES}
