#!/bin/sh

EXTRA_ARGS="$@"

exec docker run -it --privileged $EXTRA_ARGS tbb-build

