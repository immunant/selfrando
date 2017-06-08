
target_sources(selfrando_objects
    PRIVATE
    bionic/arch-arm/memcmp.S
    bionic/arch-arm/memcpy.S
    bionic/arch-arm/memset.S
    bionic/arch-arm/mmap.cpp
    )
include(bionic/arch-${SR_ARCH}/syscalls/CMakeLists.txt)
