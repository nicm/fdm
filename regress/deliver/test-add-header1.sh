#!/bin/sh
# $Id$

. ./test-deliver.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
Header: Test

EOF

cat <<EOF|test_run
match all action add-header "Header" value "Test" continue
EOF
