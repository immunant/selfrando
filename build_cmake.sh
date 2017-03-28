#!/bin/sh
# Script that builds selfrando using cmake&ninja

SR_ARCH=${SR_ARCH:-x86_64}
echo "Building for architecture: $SR_ARCH"

BUILD_DIR=out/$SR_ARCH

mkdir -p $BUILD_DIR
cd $BUILD_DIR
cmake ../.. -DCMAKE_INSTALL_PREFIX=`pwd` -DSR_ARCH=$SR_ARCH -DBUILD_SHARED_LIBS=1 -DSR_FORCE_INPLACE=1 -G Ninja $CMAKE_ARGS "$@"
ninja $NINJA_ARGS
ninja install
