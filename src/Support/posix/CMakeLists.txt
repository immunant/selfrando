
# Only build this if it's used by any enabled module;
# currently, that's only TrapLinker
if (SR_BUILD_MODULE_TRAPLINKER)
    add_library(randolib_support
        STATIC
        Debug.cpp
        Filesystem.cpp
        Misc.cpp
        )
endif()
