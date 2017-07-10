#!/bin/bash
# Tested on Ubuntu 14.04
# For testing only
# Original version by 0t1st @ github

INFO='\e[1;32m'
WARNING='\e[1;36m'
NORMAL='\e[0;m'


SCRIPT_DIR="$(cd "$(dirname "$0" )" && pwd)"
SELFRANDO_BIN=$SCRIPT_DIR/../../out/$(uname -p)/bin
if [ ! -e "$SELFRANDO_BIN/traplinker" ]; then
  echo "Build selfrando before running this script"
  exit 1
fi
WORK_DIR=`mktemp -d` && cd $WORK_DIR
PREFIX=$WORK_DIR/local/nginx
VERSION=1.9.15
SR_OPT="-g -O2 -fPIE -fstack-protector -ffunction-sections"
LD_OPT="-B$SELFRANDO_BIN -Wl,-rpath,$SELFRANDO_BIN -Wl,--gc-sections"
NUM_PROCS=`nproc --all`

# deletes the temp directory
function cleanup {
  rm -rf "$WORK_DIR"
  echo "Deleted temp working directory $WORK_DIR"
}

# register cleanup function to be called on the EXIT signal
trap cleanup EXIT

# you can add more module and option, example:
# --with-cc-opt=-g -O2 -fPIE -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2
# --with-ld-opt=-Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now
# --with-http_xslt_module
# --with-http_geoip_module
# --conf-path=/etc/nginx/nginx.conf
# --http-log-path=/var/log/nginx/access.log
# --error-log-path=/var/log/nginx/error.log
# --lock-path=/var/lock/nginx.lock
# --pid-path=/run/nginx.pid
# --http-client-body-temp-path=/var/lib/nginx/body
# --http-fastcgi-temp-path=/var/lib/nginx/fastcgi
# --http-proxy-temp-path=/var/lib/nginx/proxy
# --http-scgi-temp-path=/var/lib/nginx/scgi
# --http-uwsgi-temp-path=/var/lib/nginx/uwsgi
OPTIONS=" --prefix=${PREFIX}
            --with-debug
            --with-pcre-jit
            --with-ipv6
            --with-http_ssl_module
            --with-http_stub_status_module
            --with-http_realip_module
            --with-http_auth_request_module
            --with-http_addition_module
            --with-http_dav_module
            --with-http_gunzip_module
            --with-http_gzip_static_module
            --with-http_image_filter_module
            --with-http_v2_module
            --with-http_sub_module
            --with-stream
            --with-stream_ssl_module
            --with-mail
            --with-mail_ssl_module
            --with-threads"

command -v ab >/dev/null 2>&1 || { echo >&2 -e "${WARNING}Apache bench (ab) not found.${NORMAL}  Trying to install..."; apt-get install -f apache2-utils; }

if [ ! -d $WORK_DIR/nginx-$VERSION ];then
  echo -e "\n${INFO}Download source code in progress...${NORMAL}"
  curl -s http://nginx.org/download/nginx-$VERSION.tar.gz | tar xz
fi

if [ ! -d $WORK_DIR/nginx-$VERSION ];then
  echo -e "\n${WARNING}Nginx source code folder not found${NORMAL}"
  exit 1
fi

cd $WORK_DIR/nginx-$VERSION

./configure $OPTIONS --with-cc-opt="$SR_OPT" --with-ld-opt="$LD_OPT" ||  { echo >&2 -e "${WARNING}configure failed.${NORMAL}"; exit 1; }
echo -e "\n${INFO}Compiling nginx...${NORMAL}"
make -j$NUM_PROCS CCOPT="-w" --quiet  ||  { echo >&2 -e "${WARNING}make failed.${NORMAL}"; exit 1; }

echo -e "\n${INFO}Installing nginx...${NORMAL}"
make install CCOPT="-w" --quiet ||  { echo >&2 -e "${WARNING}make install failed.${NORMAL}"; exit 1; }
CONF=$PREFIX/conf/nginx.conf
if [ ! -f $CONF ];then
  echo -e "\n${WARNING}Nginx configuration file not found${NORMAL}"
  exit 0
fi
sed --in-place -e "s/^        listen       80;$/        listen       8080;/g" $CONF

echo -e "\n${INFO}Testing nginx...${NORMAL}"

NGINX=$PREFIX/sbin/nginx

start-stop-daemon --start --name nginx --quiet --exec $NGINX -- 
ab -d -q -n 10000 -c 10 http://127.0.0.1:8080/
start-stop-daemon --stop --name nginx

echo -e "\n${INFO}PASS!${NORMAL}"
exit 0
