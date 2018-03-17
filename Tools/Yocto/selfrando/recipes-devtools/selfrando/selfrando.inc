SUMMARY = "Selfrando load-time code randomization"
HOMEPAGE = "https://github.com/immunant/selfrando"
LICENSE = "AGPL"
LIC_FILES_CHKSUM = "file://LICENSE;md5=3bec43c7618831a8c7ae537bb2363774"

DEPENDS = "elfutils"

SRCREV = "master"
SRC_URI = "git://github.com/immunant/selfrando;protocol=https"
SRC_URI[md5sum] = "3d70d881f62ec8884eb16af2416f9fc3"
SRC_URI[sha256sum] = "b34c3fb597295fd783241f9eb70dcf5baa14125e649077577103c62ff7576cbc"

S = "${WORKDIR}/git"

