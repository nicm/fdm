#!/bin/sh
# $Id$

. ./test.subr && test_init

cat <<EOF|test_in
-%-
EOF

cat <<EOF|test_out
--
EOF

cat <<EOF|test_run
match "(.*)" action tag "test_tag" value "%1" continue
match all action rewrite "echo %[:test_tag]" continue
EOF
