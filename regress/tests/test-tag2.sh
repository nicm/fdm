#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in

EOF

cat <<EOF|test_out
tag2
EOF

cat <<EOF|test_run
match all action {
	tag "test_tag" value "tag1"
	tag "test_tag" value "tag2"
	rewrite "echo %[test_tag]"
} continue
EOF
