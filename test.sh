#!/bin/sh

if [ -z "$PROG" ]; then
	PROG="lindacol"
fi
if [ -z "$LANGU" ]; then
	LANGU="`basename $PWD`"
fi

if [ -z "$PROG" -o -z "$LANGU" ]; then
	exit
fi

rm -rf "$HOME/coding/$LANGU/$PROG"
cp -r "$HOME/d/coding/$LANGU/$PROG" "$HOME/coding/$LANGU/"
cd "$HOME/coding/$LANGU/$PROG"
clear
ls -F ..
ls -F
case "$LANGU" in
	"c++" )
		g++ "$PROG.cpp" -o "$PROG" && ./"$PROG"
	;;
	"lindacol" )
		make
	;;
esac
