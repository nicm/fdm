#!/bin/sh
# $Id$

. ./test-deliver.subr && test_init

cat <<EOF|test_in
From test@test
:0 1 2 3 4 5 6 7 8 9
EOF

cat <<EOF|test_out
:0 1 2 3 4 5 6 7 8 9
0 1 2 3 4 5 6 7 8 00
EOF

cat <<EOF|test_run
match "^:(.) (.) (.) (.) (.) (.) (.) (.) (.) (.)"
	action rewrite "cat >/dev/null;" +
	"echo %0; echo %1 %2 %3 %4 %5 %6 %7 %8 %9 %10" continue
EOF
