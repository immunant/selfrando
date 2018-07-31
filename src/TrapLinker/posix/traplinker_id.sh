#!/bin/sh

LD_OUT=$(exec $1 --version)
LINKER=$(echo $LD_OUT | grep -o "GNU.*ld")

if [ "x$LINKER" == "xGNU ld" ]; then
    exit 1
elif [ "x$LINKER" == "xGNU gold" ]; then
    exit 2
fi

exit 0

