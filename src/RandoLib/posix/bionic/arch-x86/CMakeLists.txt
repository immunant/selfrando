
target_sources(selfrando_objects
    PRIVATE
    bionic/arch-x86/bcopy.S
    bionic/arch-x86/memcmp.S
    bionic/arch-x86/memcpy.S
    bionic/arch-x86/mmap.cpp
    )
include(bionic/arch-${SR_ARCH}/syscalls/CMakeLists.txt)
