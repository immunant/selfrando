#!/bin/sh
#  Copyright (c) 2015-2019 RunSafe Security Inc.

INPUT=$1
OUTPUT=$2

: ${OBJCOPY:=$(which objcopy)}
: ${OBJDUMP:=$(which objdump)}

cp $INPUT $OUTPUT

# Find all sections in $OUTPUT that begin with .text or .rodata
SECTIONS=`$OBJDUMP -h $OUTPUT | awk '{ if ($2 ~ /^\.(text|rodata)/) print $2 }' | sort | uniq`

for section in $SECTIONS; do
    $OBJCOPY --rename-section=$section=.txtrp $OUTPUT
done
