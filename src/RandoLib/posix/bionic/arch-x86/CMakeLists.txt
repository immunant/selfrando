
list(APPEND selfrando_sources
    bionic/arch-x86/bcopy.S
    bionic/arch-x86/memcmp.S
    bionic/arch-x86/memcpy.S
    bionic/arch-x86/mmap.cpp
    bionic/arch-x86/sse2-memset-slm.S
    )
include(bionic/arch-${SR_ARCH}/syscalls/CMakeLists.txt)
