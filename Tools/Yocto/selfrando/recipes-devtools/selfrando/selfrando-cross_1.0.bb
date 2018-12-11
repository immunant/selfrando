inherit cross

include selfrando.inc

PN = "selfrando-cross-${TARGET_ARCH}"

DEPENDS += "selfrando-native"

deltask do_patch
deltask do_configure
deltask do_compile
deltask do_populate_lic

do_install () {
    n_d=`readlink -m ${D}${bindir}/../selfrando`
    c_d=`readlink -m ${D}${bindir}/selfrando`
    t_d=$c_d/${TARGET_SYS}
    install -d $c_d
    install -d $t_d
    for x in traplinker trapdump traplinker_id.sh traplinker_script.ld; do
        lnr $n_d/$x $c_d/$x
        lnr $n_d/$x $t_d/$x
    done
    for x in ld ld.bfd ld.gold; do
        lnr $c_d/traplinker $c_d/${TARGET_PREFIX}$x
        lnr $c_d/traplinker $t_d/$x
    done
}
