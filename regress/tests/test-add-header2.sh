#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in
Body
EOF

cat <<EOF|test_out
Header: Test

Body
EOF

cat <<EOF|test_run
match all action add-header "Header" value "Test" continue
EOF
