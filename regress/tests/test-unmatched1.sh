#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out

EOF

cat <<EOF|test_run
match all action tag "tag" continue
match unmatched action rewrite "echo test" continue
EOF
