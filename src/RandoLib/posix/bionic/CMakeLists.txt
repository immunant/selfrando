
list(APPEND selfrando_sources
    bionic/libc/open.cpp
    bionic/stubs/set_errno_internal.c
    bionic/upstream-netbsd/rand_r.c
    bionic/upstream-openbsd/getenv.c
    bionic/upstream-openbsd/time.c
    )
include_directories(
    bionic
    bionic/arch-${SR_ARCH}
    )
include(bionic/arch-${SR_ARCH}/CMakeLists.txt)
