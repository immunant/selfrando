
target_sources(selfrando_objects
    PRIVATE
    bionic/libc/open.cpp
    bionic/stubs/set_errno_internal.c
    bionic/upstream-netbsd/rand_r.c
    bionic/upstream-openbsd/getenv.c
    bionic/upstream-openbsd/time.c
    )
target_include_directories(selfrando_objects
    PRIVATE
    bionic
    bionic/arch-${SR_ARCH}
    )
include(bionic/arch-${SR_ARCH}/CMakeLists.txt)
