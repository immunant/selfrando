#!/bin/sh
#
# This file is part of selfrando.
# Copyright (c) 2015-2017 Immunant Inc.
# For license information, see the LICENSE file
# included with selfrando.
#

set -ue

OUTDIR=$1

mkdir -p $OUTDIR
cd $OUTDIR

LIBELF_VER="0.168"
LIBELF_FILE="elfutils-$LIBELF_VER.tar.bz2"
LIBELF_URL="https://fedorahosted.org/releases/e/l/elfutils/$LIBELF_VER/$LIBELF_FILE"

wget -O $LIBELF_FILE $LIBELF_URL
tar xjf $LIBELF_FILE

NUM_PROCS=`nproc --all`

cd "elfutils-$LIBELF_VER"
./configure --quiet --prefix=$OUTDIR/libelf-prefix
make --quiet -j$NUM_PROCS
make --quiet install
