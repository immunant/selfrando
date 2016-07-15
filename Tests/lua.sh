#! /bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0" )" && pwd)"
WRAPPER_DIR=$SCRIPT_DIR/../Tools/Wrappers/GCC
WORK_DIR=`mktemp -d` && cd $WORK_DIR

# deletes the temp directory
function cleanup {
  rm -rf "$WORK_DIR"
  echo "Deleted temp working directory $WORK_DIR"
}

# register cleanup function to be called on the EXIT signal
trap cleanup EXIT

curl http://www.lua.org/ftp/lua-5.3.2.tar.gz | tar xz
curl http://www.lua.org/tests/lua-5.3.2-tests.tar.gz | tar xz

LUA_HOME=$WORK_DIR/lua-5.3.2
LUA_TEST_HOME=$WORK_DIR/lua-5.3.2-tests

cd $LUA_HOME
$WRAPPER_DIR/srenv make linux

cd $LUA_TEST_HOME
$LUA_HOME/src/lua -e_U=true all.lua
