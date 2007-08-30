#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
file2
EOF

cat <<EOF|test_run
\$test="file1"
\$test="file2"
match all action rewrite "echo \${test}" continue
EOF
