#!/bin/sh
# $Id$

. ./test-deliver.subr && test_init

cat <<EOF|test_in
Header: Test1

Body
EOF

cat <<EOF|test_out
Header: Test1
Header: Test2

Body
EOF

cat <<EOF|test_run
match all action add-header "Header" value "Test2" continue
EOF
