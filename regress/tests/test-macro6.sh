#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
1
EOF

cat <<EOF|test_run
%test=1
match all action rewrite "echo %{test}" continue
EOF
