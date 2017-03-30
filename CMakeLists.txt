cmake_minimum_required(VERSION 3.3)
project(selfrando LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 11)

set(SR_ALL_MODULES "TrapLinker;RandoLib;TrapDump")
set(SR_BUILD_MODULES "all" CACHE STRING "Selfrando modules to build \
(Semicolon-separated list of modules, e.g. ${SR_ALL_MODULES}, or 'all'")

set(SR_ARCH "x86_64" CACHE STRING "Target architectures")
set(SR_DEBUG_LEVEL "0" CACHE STRING "Debugging level (0-10); set to 'env' to control via environment variable")
set(ANDROID_NDK "" CACHE PATH "Android NDK directory (build libs for Android)")
set(LIBELF_PATH "" CACHE PATH "Path to directory containing libelf.so (if not using system libelf)")

if(${SR_BUILD_MODULES} STREQUAL "all")
    set(SR_BUILD_MODULES ${SR_ALL_MODULES})
endif()
foreach(module ${SR_BUILD_MODULES})
    string(TOUPPER "${module}" upper_module)
    set(SR_BUILD_MODULE_${upper_module} 1)
endforeach()

set(ALL_ARCHES x86 x86_64 arm arm64)
set(ARCH_SIZES 32 64 32 64)
set_property(CACHE SR_ARCH PROPERTY STRINGS ${ALL_ARCHES})
list(FIND ALL_ARCHES ${SR_ARCH} arch_idx)
if(arch_idx LESS 0)
    message(FATAL_ERROR "Unknown architecture '${SR_ARCH}', "
                        "must be one of '${ALL_ARCHES}'!")
endif()
list(GET ARCH_SIZES ${arch_idx} SR_ARCH_SIZE)

if("${SR_DEBUG_LEVEL}" STREQUAL "env")
    set(SR_DEBUG_LEVEL_IS_ENV 1)
    set(SR_DEBUG_LEVEL 0)
else()
    set(SR_DEBUG_LEVEL_IS_ENV 0)
endif()

if(WIN32)
    set(SR_PLATFORM win32)
    # TODO: add win32 options
elseif(UNIX)
    set(SR_PLATFORM posix)
    
    add_compile_options(
        -fno-omit-frame-pointer
        -Wall
        -Wextra
        -Wno-unused-parameter
        -Wpointer-arith
        )

    find_library(SR_LIBELF_LIB
        libelf.a
        HINTS "${LIBELF_PATH}"
        PATH_SUFFIXES bin lib
        )
endif()

string(TOUPPER "${SR_PLATFORM}" upper_platform)
string(TOUPPER "${SR_ARCH}" upper_arch)
add_definitions(
    -DRANDOLIB_IS_${upper_platform}=1
    -DRANDOLIB_IS_${upper_arch}=1
    -DRANDOLIB_ARCH="${SR_ARCH}"
    -DRANDOLIB_ARCH_SIZE=${SR_ARCH_SIZE}
    -DRANDOLIB_DEBUG_LEVEL=${SR_DEBUG_LEVEL}
    -DRANDOLIB_DEBUG_LEVEL_IS_ENV=${SR_DEBUG_LEVEL_IS_ENV}
    )
if(ANDROID_NDK)
    add_definitions(-DRANDOLIB_IS_ANDROID=1)
endif()

add_subdirectory(src)

