#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
test
EOF

cat <<EOF|test_run
match unmatched action rewrite "echo test" continue
EOF
