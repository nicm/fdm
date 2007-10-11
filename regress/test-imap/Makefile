# $Id$

CLEANFILES= *~ *.fifo.{in,out} *.log *.conf

TESTFILES!= echo imap-*.test

TARGETS=
.for n in ${TESTFILES}
TARGETS+= ${n}
${n}:
		@HOME=. FDM=../../fdm sh test-imap.sh ${n}
.endfor

.MAIN:		all
.PHONY: 	regress clean ${TARGETS}
.PRECIOUS: 	${TARGETS}

all:		regress

regress:	${TARGETS}

clean:
		rm -f ${CLEANFILES}
