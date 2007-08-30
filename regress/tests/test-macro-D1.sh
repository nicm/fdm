#!/bin/sh
# $Id$

FDM="$FDM -D\$test=argument"
. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
argument
EOF

cat <<EOF|test_run
\$test="file"
match all action rewrite "echo \${test}" continue
EOF
