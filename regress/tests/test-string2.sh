#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in
Message-Id: test

EOF

cat <<EOF|test_out
test
EOF

cat <<EOF|test_run
match not string "%[message_id]" 
	to case "T..T" action rewrite "echo test" continue
EOF
