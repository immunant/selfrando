#!/bin/sh
#
# This file is part of selfrando.
# Copyright (c) 2015-2019 RunSafe Security Inc.
# For license information, see the LICENSE file
# included with selfrando.
#

set -ue

OUTDIR=$1

mkdir -p $OUTDIR
cd $OUTDIR

LIBELF_VER="0.176"
LIBELF_FILE="elfutils_$LIBELF_VER.orig.tar.bz2"
LIBELF_URL="http://deb.debian.org/debian/pool/main/e/elfutils/$LIBELF_FILE"

wget -O $LIBELF_FILE $LIBELF_URL
tar xjf $LIBELF_FILE

NUM_PROCS=`nproc --all`
CC=gcc # doesn't build with clang

cd "elfutils-$LIBELF_VER"
./configure --quiet --prefix=$OUTDIR/libelf-prefix
make --quiet -j$NUM_PROCS
make --quiet install
