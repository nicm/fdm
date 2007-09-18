#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in
Message-Id: xtest

EOF

cat <<EOF|test_out
test
EOF

cat <<EOF|test_run
match not string "%[message_id]" == "test" action rewrite "echo test" continue
EOF
