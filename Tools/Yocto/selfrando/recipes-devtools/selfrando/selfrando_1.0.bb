include selfrando.inc

inherit cmake

DEPENDS += "elfutils"

EXTRA_OECMAKE = " \
    -DSR_FORCE_INPLACE=1 \
    -DSR_DEBUG_LEVEL=env \
    -DSR_LOG=console \
"

EXTRA_OECMAKE_append_class-native = " \
    -DSR_BUILD_MODULES="TrapLinker;TrapDump" \
    -DSR_ARCH=${BUILD_ARCH} \
"

EXTRA_OECMAKE_append_class-nativesdk = " \
    -DSR_BUILD_MODULES="TrapLinker;TrapDump" \
    -DSR_ARCH=${BUILD_ARCH} \
"

EXTRA_OECMAKE_append_class-target = " \
    -DSR_BUILD_MODULES="TrapLinker;TrapDump;RandoLib" \
    -DSR_ARCH=${TARGET_ARCH} \
    -DBUILD_SHARED_LIBS=1 \
"

do_install() {
    install -d ${D}${bindir}/selfrando
    install -m 0755 ${B}/src/TrapLinker/posix/traplinker ${D}${bindir}/selfrando/traplinker
    install -m 0755 ${B}/src/TrapInfo/trapdump ${D}${bindir}/selfrando/trapdump
    install -m 0755 ${S}/src/TrapLinker/posix/linker_id.sh ${D}${bindir}/selfrando/linker_id.sh
    install -m 0644 ${S}/src/TrapLinker/posix/linker_script.ld ${D}${bindir}/selfrando/linker_script.ld
}

do_install_append_class-target() {
    # TODO: install static libselfrando.a and page-alignment libs
    install -d ${D}${libdir}
    install -m 0755 ${B}/src/RandoLib/posix/libselfrando.so ${D}${libdir}/libselfrando.so
    for l in randoentry_exec randoentry_so trapheader trapfooter trapfooter_nopage; do
        install -m 0644 ${B}/src/RandoLib/posix/lib$l.a ${D}${libdir}/lib$l.a
    done
}

FILES_${PN} = "${libdir}/libselfrando.so"
FILES_${PN}-dev = "${bindir}/selfrando"

RDEPENDS_${PN}_class-target += "grep"

BBCLASSEXTEND = "native nativesdk"
