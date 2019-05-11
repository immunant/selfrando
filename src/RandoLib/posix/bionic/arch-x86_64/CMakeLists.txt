
list(APPEND selfrando_sources
    bionic/arch-x86_64/sse2-memcpy-slm.S
    bionic/arch-x86_64/sse4-memcmp-slm.S
    bionic/arch-x86_64/sse2-memset-slm.S
    )
include(bionic/arch-${SR_ARCH}/syscalls/CMakeLists.txt)
