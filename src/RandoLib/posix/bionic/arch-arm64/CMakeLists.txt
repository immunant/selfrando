
target_sources(selfrando_objects
    PRIVATE
    bionic/arch-arm64/memcmp.S
    bionic/arch-arm64/memcpy.S
    bionic/arch-arm64/memcpy_base.S
    bionic/arch-arm64/memset.S
    )
include(bionic/arch-${SR_ARCH}/syscalls/CMakeLists.txt)
