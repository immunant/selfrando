FROM ubuntu:14.04.5

RUN apt-get update && apt-get -y install torsocks tor ruby apache2 git apt-cacher-ng qemu-kvm virt-what lxc lxctl fakeroot faketime zip unzip subversion debian-archive-keyring curl pkg-config libgtk2.0-dev libglib2.0-dev sudo libyaml-perl libfile-slurp-perl libxml-writer-perl libio-captureoutput-perl libparallel-forkmanager-perl libxml-libxml-perl libwww-perl libjson-perl
RUN apt-get -y install python-cheetah parted kpartx

ARG jobs=4
ARG mem=8192
ENV NUM_PROCS=$jobs
ENV VM_MEMORY=$mem

ARG user
ARG password
ARG useruid=1000
ARG usergid=1000
ARG kvmgid
RUN groupadd -g $usergid $user && useradd -m -u $useruid -g $user $user && groupadd libvirtd && adduser $user libvirtd && adduser $user kvm && adduser $user sudo && groupadd -g $kvmgid hostkvm && adduser $user hostkvm
RUN echo "$user:$password" | chpasswd

RUN cd /root && wget -U "" https://bugs.launchpad.net/ubuntu/+archive/primary/+files/vm-builder_0.12.4+bzr494.orig.tar.gz && tar -zxvf vm-builder_0.12.4+bzr494.orig.tar.gz && cd vm-builder-0.12.4+bzr494 && python setup.py install

USER $user 
CMD apt-cacher-ng && exec /bin/bash

