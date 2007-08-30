# $Id$

CLEANFILES= *~ *.in *.out *.data *.conf

TESTFILES!= echo *.sh

TARGETS=
.for n in ${TESTFILES}
TARGETS+= ${n}
${n}:
		@HOME=. FDM=../../fdm sh ${n}
.endfor

.MAIN:		all
.PHONY: 	regress clean ${TARGETS}
.PRECIOUS: 	${TARGETS}

all:		regress

regress:	${TARGETS}

clean:
		rm -f ${CLEANFILES}
