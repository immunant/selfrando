#!/bin/sh

EXTRA_ARGS="$@"

USERUID=`id -u`
KVMGID=`stat --printf="%g" /dev/kvm`

exec docker build -t tbb-build --force-rm=true --build-arg user=$USER --build-arg useruid=$USERUID --build-arg kvmgid=$KVMGID $EXTRA_ARGS .

