#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out

EOF

cat <<EOF|test_run
match matched action rewrite "echo test" continue
EOF
