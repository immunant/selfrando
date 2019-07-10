#!/bin/sh
# Copyright (c) 2015-2019 RunSafe Security Inc.
# Script that builds selfrando using cmake&ninja

SR_ARCH=${SR_ARCH:-x86_64}
echo "Building for architecture: $SR_ARCH"

SR_DIR=$(readlink -f $(dirname $0)/..)
BUILD_DIR=$SR_DIR/out/$SR_ARCH
echo "Building in directory: $BUILD_DIR"

set -e

mkdir -p $BUILD_DIR
cd $BUILD_DIR
cmake $SR_DIR -DCMAKE_INSTALL_PREFIX:PATH="$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DSR_ARCH=$SR_ARCH -DSR_FORCE_INPLACE=1 -G Ninja $CMAKE_ARGS "$@"
ninja $NINJA_ARGS
ninja install
