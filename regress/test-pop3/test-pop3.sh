#!/bin/sh
# $Id$

[ -z "$FDM" ] && exit 1

TEST=$1
FIFO=$TEST.fifo
TYPE=pop3

trap "rm -f $FIFO.in $FIFO.out $TEST.log $TEST.conf; exit 1" 2 3

cat <<EOF >$TEST.conf
set lock-file "$TEST.lock"
account 'account' $TYPE
	pipe "cat $FIFO.in & cat >$FIFO.out" user "test" pass "test"
match all action drop
EOF

rm -f $FIFO.in $FIFO.out
mkfifo $FIFO.in $FIFO.out

$FDM -mvvvv -f $TEST.conf f >$TEST.log 2>&1 &
cat $FIFO.out |&

quit() {
    rm -f $FIFO.in $FIFO.out $TEST.conf
    [ "$DEBUG" = "" ] && rm -f $TEST.log
    
    if [ $1 -ne 1 ]; then
	echo "$TEST: PASSED"
    else
	echo "$TEST: FAILED"
    fi

    exit $1
}

awk '/^\>/ { print substr($0, 2) }' $TEST >$FIFO.in
awk '/^\</ { print substr($0, 2) }; /^--$/ { print "--" }' $TEST|\
while read i; do
    if [ "$i" != "--" ]; then
	read -p j
    
	if [ "$DEBUG" != "" ]; then
	    echo IN:  $i
	    echo OUT: $j
	fi
	[ "$i" = "$j" ] || quit 1

	continue;
    fi

    MSG=`tail -1 $TEST`
    grep "^account: $MSG" $TEST.log >/dev/null || quit 1
    grep "^account: fetching error. aborted" $TEST.log >/dev/null || quit 1
    quit 2
done

if [ $? -eq 0 ]; then
    grep "^account: [0-9]* messages processed" $TEST.log >/dev/null || quit 1
    quit 0
fi
