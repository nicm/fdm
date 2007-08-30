#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in
Header: Test
Header: Test

EOF

cat <<EOF|test_out

EOF

cat <<EOF|test_run
match all action remove-header "Header" continue
EOF
