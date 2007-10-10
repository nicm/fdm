#!/bin/sh
# $Id$

[ -z "$FDM" ] && exit 1

TEST=$1
FIFO=$TEST.fifo
TYPE=pop3

cat <<EOF >$TEST.conf
set lock-file "$TEST.lock"
account 'account' $TYPE
	pipe "cat $FIFO.in & cat >$FIFO.out" user "test" pass "test"
match all action drop
EOF

rm -f $FIFO.in $FIFO.out
mkfifo $FIFO.in $FIFO.out || exit 1

$FDM -mvvvv -f $TEST.conf f >$TEST.log 2>&1 &
PID=$!
cat $FIFO.out |&

hold() {
    while kill -0 $! 2>/dev/null; do
	perl -e 'select(undef,undef,undef,0.01)'
    done
}
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

awk '/^\>/ { print substr($0, 2) }' $TEST >$FIFO.in || exit 1
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

    hold
    MSG=`tail -1 $TEST`
    grep "^account: $MSG" $TEST.log >/dev/null || quit 1
    grep "^account: fetching error. aborted" $TEST.log >/dev/null || quit 1
    quit 2
done

if [ $? -eq 0 ]; then
    hold
    grep "^account: [0-9]* messages processed" $TEST.log >/dev/null || quit 1
    quit 0
fi
