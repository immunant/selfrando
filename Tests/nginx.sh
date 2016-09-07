#!/bin/bash
# Tested on Ubuntu 14.04
# For testing only
# Just for fun

INFO='\e[1;32m'
WARNING='\e[1;36m'
NORMAL='\e[0;m'
PWD=$(pwd)
NGINX_FIRST_INSTALL=1

#Default value
BENCHMARK='Y' # Benchmark nginx after compilation and installation of new binary
LISTEN=80 # Port to benchmark nginx, on fresh/first install, default is 80, if you replace an existing nginx, check your conf
MAKEINSTALL='N' # On first install, where nginx is not present on your system, you have to make install
COPYBINARY='N' # On replace install, where nginx is always present on your system, you can backup dist binary, copy new binary do a benchmark and undo the change
RESET='Y' # Reverse change to original binary, only in replace install
LIBRARIES='Y' # Install libraries for nginx module before compilation, libxslt ...

# you can add more module and option, example :
# --with-cc-opt=-g -O2 -fPIE -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2
# --with-ld-opt=-Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now
# --with-http_xslt_module
# --with-http_geoip_module
OPTIONS=" --prefix=/usr/share/nginx
            --conf-path=/etc/nginx/nginx.conf
            --http-log-path=/var/log/nginx/access.log
            --error-log-path=/var/log/nginx/error.log
            --lock-path=/var/lock/nginx.lock
            --pid-path=/run/nginx.pid
            --http-client-body-temp-path=/var/lib/nginx/body
            --http-fastcgi-temp-path=/var/lib/nginx/fastcgi
            --http-proxy-temp-path=/var/lib/nginx/proxy
            --http-scgi-temp-path=/var/lib/nginx/scgi
            --http-uwsgi-temp-path=/var/lib/nginx/uwsgi
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

if [ ! -f $PWD/selfrando/Tools/Wrappers/GCC/srenv ];then
  git clone https://github.com/immunant/selfrando.git
  sudo apt-get install -f scons pkg-config libelf-dev zlib1g-dev
  cd $PWD/selfrando/
  scons
  cd ..
fi

WRAPPER_DIR=$PWD/selfrando/Tools/Wrappers/GCC

if dpkg -l nginx | egrep 'ii.*nginx' > /dev/null 2>&1; then
  echo -e "\n${INFO}Current version of nginx:${NORMAL}"
  nginx -v
  VERSION=$(dpkg -s nginx | grep 'Version' | cut -d ' ' -f2 | cut -d '-' -f1)
  echo -e '\n'
  read -p "$(echo -e ${INFO}Enter distribution version [$VERSION] or choose a different one:${NORMAL})`echo $'\n> '`" READ
  VERSION=${READ:-$VERSION}
  # retrieve dist compile options
  #OPTIONS=$(2>&1 nginx -V | xargs -n1 | grep "^--" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g')
  NGINX_FIRST_INSTALL=0
else
  echo -e '\n'
  read -p "$(echo -e ${INFO}Enter version number you want to install:${NORMAL})`echo $'\n> '`" VERSION
fi

echo -e '\n'
read -p "$(echo -e ${INFO}Benchmark after install ? [$BENCHMARK]${NORMAL})`echo $'\n> '`" READ
BENCHMARK=${READ:-$BENCHMARK}
case $BENCHMARK in
    [yY])
        echo -e '\n'
        read -p "$(echo -e ${INFO}Default port to benchmark [$LISTEN]:${NORMAL})`echo $'\n> '`" READ
        LISTEN=${READ:-$LISTEN}
        BENCHMARK=1
        command -v ab >/dev/null 2>&1 || { echo >&2 -e "${WARNING}Apache bench (ab) not found.${NORMAL}  Trying to install..."; apt-get install -f apache2-utils; }
        ;;
esac

if [ ! -d $PWD/nginx-$VERSION ];then
  echo -e "\n${INFO}Download source code in progress...${NORMAL}"
  curl http://nginx.org/download/nginx-$VERSION.tar.gz | tar xz
fi

if [ ! -d $PWD/nginx-$VERSION ];then
  echo -e "\n${WARNING}Nginx source code folder not found${NORMAL}"
  exit 0
fi

cd $PWD/nginx-$VERSION

if [ ! -f objs/nginx ];then
  echo -e '\n'
  read -p "$(echo -e ${INFO}Install libraries dependencies to compile nginx ? [$LIBRARIES]${NORMAL})`echo $'\n> '`" READ
  LIBRARIES=${READ:-$LIBRARIES}
  case $LIBRARIES in
      [yY])
        sudo add-apt-repository ppa:maxmind/ppa
        sudo apt-get update
        sudo apt-get install -f libxml2-dev libxml2 libxslt1-dev libgd-dev libperl-dev libgd2-xpm-dev geoipupdate
        sudo ldconfig
        ;;
  esac
  $WRAPPER_DIR/srenv ./configure $OPTIONS ||  { echo >&2 -e "${WARNING}configure failed.${NORMAL}"; exit 1; }
  $WRAPPER_DIR/srenv make CCOPT="--no-warn" --quiet  ||  { echo >&2 -e "${WARNING}make failed.${NORMAL}"; exit 1; }
fi

if [ "$NGINX_FIRST_INSTALL" -eq 1 ];then
  echo -e '\n'
  read -p "$(echo -e ${INFO}Do a make install ? [$MAKEINSTALL]${NORMAL})`echo $'\n> '`" READ
  MAKEINSTALL=${READ:-$MAKEINSTALL}
  case $MAKEINSTALL in
      [yY])
          $WRAPPER_DIR/srenv make install CCOPT="--no-warn" --quiet ||  { echo >&2 -e "${WARNING}make install failed.${NORMAL}"; exit 1; }
          #@TODO Do benchmark after init script install and service installation
          echo "${INFO}Make install finished, install init script and test benchmark manually${NORMAL}"
          exit 0
          ;;
  esac
else
  echo -e '\n'
  read -p "$(echo -e ${INFO}Copy new binary in /usr/sbin ? [$COPYBINARY]${NORMAL})`echo $'\n> '`" READ
  COPYBINARY=${READ:-$COPYBINARY}
  case $COPYBINARY in
      [yY])
          echo -e "\n${INFO}Current nginx version${NORMAL}"
          /usr/sbin/nginx -v
          echo -e "\n${INFO}Stop nginx service${NORMAL}"
          sudo /etc/init.d/nginx stop
          echo -e "\n${INFO}Copy new version${NORMAL}"
          sudo mv /usr/sbin/nginx /usr/sbin/nginx-dist
          sudo cp objs/nginx /usr/sbin/nginx
          sudo chmod +x /usr/sbin/nginx
          echo -e "\n${INFO}New nginx version${NORMAL}"
          /usr/sbin/nginx -v
          if [ "$BENCHMARK" -eq 1 ];then
            echo -e "\n${INFO}Restart nginx service${NORMAL}"
            sudo /etc/init.d/nginx start
            echo -e "\n${INFO}Start benchmark${NORMAL}"
            ab -d -q -n 10000 -c 10 http://127.0.0.1:$LISTEN/
          fi
          echo -e '\n'
          read -p "$(echo -e ${INFO}Undo nginx binary to distribution version ? [$RESET]${NORMAL})`echo $'\n> '`" READ
          RESET=${READ:-$RESET}
          case $RESET in
              [yY])
                  echo -e "\n${INFO}Stopping service${NORMAL}"
                  sudo /etc/init.d/nginx stop
                  echo -e "\n${INFO}Backup dist version${NORMAL}"
                  sudo mv /usr/sbin/nginx /usr/sbin/nginx-hardened
                  sudo mv /usr/sbin/nginx-dist /usr/sbin/nginx
                  sudo chmod +x /usr/sbin/nginx-hardened
                  echo -e "\n${INFO}Check current version${NORMAL}"
                  /usr/sbin/nginx -v
                  echo -e "\n${INFO}Restart service${NORMAL}"
                  sudo /etc/init.d/nginx start
                  echo -e "\n${INFO}Check process${NORMAL}"
                  sudo ps -ef | grep nginx
                  ;;
          esac
          ;;
      *)
          echo -e "\n${INFO}Compilation finished, nginx binary in nginx-$VERSION/objs/${NORMAL}"
          ;;
  esac
fi

echo -e "\n${INFO}Quit...${NORMAL}"
exit 0
