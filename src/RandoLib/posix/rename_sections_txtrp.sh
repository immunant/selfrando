#!/bin/sh

INPUT=$1
OUTPUT=$2

cp $INPUT $OUTPUT

# Find all sections in $OUTPUT that begin with .text or .rodata
SECTIONS=`objdump -h $OUTPUT | awk '{ if ($2 ~ /^\.(text|rodata)/) print $2 }' | sort | uniq`

for section in $SECTIONS; do
    objcopy --rename-section=$section=.txtrp $OUTPUT
done
