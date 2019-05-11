include selfrando.inc

inherit cmake

DEPENDS += "elfutils"

EXTRA_OECMAKE = " \
    -DSR_FORCE_INPLACE=1 \
    -DSR_DEBUG_LEVEL=env \
    -DSR_LOG=console \
"

def map_selfrando_arch(bb, d, arch_var):
    a = d.getVar(arch_var)
    if a.startswith("aarch64"):
        return "arm64"
    else:
        return a

EXTRA_OECMAKE_append_class-native = " \
    -DSR_BUILD_MODULES="TrapLinker;TrapDump" \
    -DSR_ARCH=${@map_selfrando_arch(bb, d, "BUILD_ARCH")} \
"

EXTRA_OECMAKE_append_class-nativesdk = " \
    -DSR_BUILD_MODULES="TrapLinker;TrapDump" \
    -DSR_ARCH=${@map_selfrando_arch(bb, d, "BUILD_ARCH")} \
"

EXTRA_OECMAKE_append_class-target = " \
    -DSR_BUILD_MODULES="TrapLinker;TrapDump;RandoLib;TrapLibs" \
    -DSR_ARCH=${@map_selfrando_arch(bb, d, "TARGET_ARCH")} \
"

do_install() {
    install -d ${D}${bindir}/selfrando
    install -m 0755 ${B}/src/TrapLinker/posix/traplinker ${D}${bindir}/selfrando/traplinker
    install -m 0755 ${B}/src/TrapInfo/trapdump ${D}${bindir}/selfrando/trapdump
    install -m 0755 ${S}/src/TrapLinker/posix/traplinker_id.sh ${D}${bindir}/selfrando/traplinker_id.sh
    install -m 0644 ${S}/src/TrapLinker/posix/traplinker_script.ld ${D}${bindir}/selfrando/traplinker_script.ld
}

do_install_append_class-target() {
    # TODO: install static libselfrando.a and page-alignment libs
    install -d ${D}${libdir}
    install -m 0755 ${B}/src/RandoLib/posix/libselfrando.so ${D}${libdir}/libselfrando.so
    for l in randoentry_exec randoentry_so; do
        install -m 0644 ${B}/src/RandoLib/posix/lib$l.a ${D}${libdir}/lib$l.a
    done
    for l in trapheader trapfooter trapfooter_nopage; do
        install -m 0644 ${B}/src/TrapLibs/posix/lib$l.a ${D}${libdir}/lib$l.a
    done
}

FILES_${PN} = "${libdir}/libselfrando.so"
FILES_${PN}-dev = "${bindir}/selfrando"

RDEPENDS_${PN}_class-target += "grep"

BBCLASSEXTEND = "native nativesdk"
