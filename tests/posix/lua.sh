#! /bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0" )" && pwd)"
SELFRANDO_BIN=$SCRIPT_DIR/../../out/$(uname -p)/bin
if [ ! -e "$SELFRANDO_BIN/traplinker" ]; then
  echo "Build selfrando before running this script"
  exit 1
fi
WORK_DIR=`mktemp -d` && cd $WORK_DIR

# deletes the temp directory
function cleanup {
  rm -rf "$WORK_DIR"
  echo "Deleted temp working directory $WORK_DIR"
}

# register cleanup function to be called on the EXIT signal
trap cleanup EXIT

curl -s http://www.lua.org/ftp/lua-5.3.3.tar.gz | tar xz
curl -s http://www.lua.org/tests/lua-5.3.3-tests.tar.gz | tar xz

LUA_HOME=$WORK_DIR/lua-5.3.3
LUA_TEST_HOME=$WORK_DIR/lua-5.3.3-tests
NUM_PROCS=`nproc --all` 

cd $LUA_HOME
sed --in-place -e 's/^CC=/CC?=/g' ./src/Makefile
MYCFLAGS="-ffunction-sections -fPIC"
MYLDFLAGS="-B$SELFRANDO_BIN -Wl,-rpath,$SELFRANDO_BIN -Wl,--gc-sections" 
make linux -j$NUM_PROCS MYCFLAGS="$MYCFLAGS" MYLDFLAGS="$MYLDFLAGS"

cd $LUA_TEST_HOME
$LUA_HOME/src/lua -e_U=true all.lua
