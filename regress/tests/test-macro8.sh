#!/bin/sh
# $Id$

FDM="$FDM -D%test1=1 -D%test2=2"
. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
1 2
EOF

cat <<EOF|test_run
%test1=3
%test2=4
match all action rewrite "echo %{test1} %{test2}" continue
EOF
