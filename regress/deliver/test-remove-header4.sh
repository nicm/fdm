#!/bin/sh
# $Id$

. ./test-deliver.subr && test_init

cat <<EOF|test_in
Header: Test
Header2: Test
Header: Test

EOF

cat <<EOF|test_out
Header2: Test

EOF

cat <<EOF|test_run
match all action remove-header "Header" continue
EOF
