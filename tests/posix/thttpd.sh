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

curl --silent http://acme.com/software/thttpd/thttpd-2.27.tar.gz | tar xz

command -v ab >/dev/null 2>&1 || { echo >&2 "Apache bench (ab) not found.  Aborting."; exit 1; }

NUM_PROCS=`nproc --all`
cd thttpd-2.27

SED_EXPR="s/^CCOPT =\s*\@V_CCOPT\@$/CCOPT = \t\@V_CCOPT\@ \$(CC_ADDN_OPT)/g"
sed --in-place -e "$SED_EXPR" Makefile.in
sed --in-place -e "$SED_EXPR" cgi-src/Makefile.in
sed --in-place -e "$SED_EXPR" extras/Makefile.in

CFLAGS="-ffunction-sections -fPIC -w"
LDFLAGS="-B$SELFRANDO_BIN -Wl,-rpath,$SELFRANDO_BIN -Wl,--gc-sections"
CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" ./configure --quiet --host="i686-pc-linux-gnu"

make --quiet -j$NUM_PROCS STATICFLAG= CC_ADDN_OPT="$CFLAGS" || { echo >&2 "Errors during compilation. Aborting."; exit 1; }

$SELFRANDO_BIN/trapdump $PWD/thttpd > /dev/null || { echo  >&2 "Trapdump reported an error. Aborting."; exit 1; }

start-stop-daemon --start --name thttpd --quiet --exec $PWD/thttpd -- -p 8080 -l /dev/null
ab -d -q -n 10000 -c 10 http://localhost:8080/
start-stop-daemon --stop --name thttpd
