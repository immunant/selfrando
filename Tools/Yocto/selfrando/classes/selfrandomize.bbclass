
SELFRANDO_PATH = "${STAGING_BINDIR_TOOLCHAIN}/selfrando"
SELFRANDO_BPREFIX_ARGS = "-B${SELFRANDO_PATH} -B${SELFRANDO_PATH}/${TARGET_SYS}"

DEPENDS_append_class-target = " selfrando-native selfrando-cross-${TARGET_ARCH} selfrando"
PATH_prepend_class-target = "${SELFRANDO_PATH}:"
TARGET_CC_ARCH_prepend_class-target = "${SELFRANDO_BPREFIX_ARGS} -ffunction-sections -fPIC "
TARGET_LD_ARCH_prepend_class-target = "${SELFRANDO_BPREFIX_ARGS} -Wl,--gc-sections "

def find_original_linker(d):
    path = d.getVar('PATH')
    # Strip the SELFRANDO_PATH away
    sr_path = d.getVar('SELFRANDO_PATH') + ':'
    path = path.replace(sr_path, '')

    ld = d.getVar('LD').split()[0]
    #bb.debug(1, "Looking for {} in '{}'...".format(ld, path))
    return bb.utils.which(path, ld, executable=True)

export SELFRANDO_ORIGINAL_LINKER = "${@find_original_linker(d)}"
