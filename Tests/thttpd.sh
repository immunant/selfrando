#! /bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WRAPPER_DIR=$SCRIPT_DIR/../Tools/Wrappers/GCC
WORK_DIR=`mktemp -d` && cd $WORK_DIR

# deletes the temp directory
function cleanup {
  rm -rf "$WORK_DIR"
  echo "Deleted temp working directory $WORK_DIR"
}

# register cleanup function to be called on the EXIT signal
trap cleanup EXIT

curl http://acme.com/software/thttpd/thttpd-2.27.tar.gz | tar xz

command -v ab >/dev/null 2>&1 || { echo >&2 "Apache bench (ab) not found.  Aborting."; exit 1; }
#ab

cd thttpd-2.27
./configure --quiet --host="i686-pc-linux-gnu"
$WRAPPER_DIR/srenv make CCOPT="--no-warn" 
start-stop-daemon --start --name thttpd --quiet --exec $PWD/thttpd -- -p 8080 -l /dev/null
ab -d -q -n 10000 -c 10 http://localhost:8080/
start-stop-daemon --stop --name thttpd
