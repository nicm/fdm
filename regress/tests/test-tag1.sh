#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
tag
EOF

cat <<EOF|test_run
match all action {
	tag "test_tag" value "tag"
	rewrite "echo %[test_tag]"
} continue
EOF
