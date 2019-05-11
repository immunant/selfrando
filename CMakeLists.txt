cmake_minimum_required(VERSION 3.3)
project(selfrando LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 11)

# Include CMAKE_INSTALL_*DIR variables
include(GNUInstallDirs)

set(SR_ALL_MODULES "TrapLinker;RandoLib;TrapDump;TrapLibs")
set(SR_BUILD_MODULES "all" CACHE STRING "Selfrando modules to build \
(Semicolon-separated list of modules, e.g. ${SR_ALL_MODULES}, or 'all'")

set(SR_ARCH "x86_64" CACHE STRING "Target architectures")
set(SR_DEBUG_LEVEL "0" CACHE STRING "Debugging level (0-10); set to 'env' to control via environment variable")
set(LIBELF_PATH "" CACHE PATH "Path to directory containing libelf.so (if not using system libelf)")
set(SR_BUILD_LIBELF OFF CACHE BOOL "Build our own libelf as part of the build process")

set(BAREFLANK_DIR "" CACHE PATH "Path to bareflank hypervisor repository")

if("${SR_BUILD_MODULES}" STREQUAL "all")
    set(SR_BUILD_MODULES ${SR_ALL_MODULES})
endif()
foreach(module ${SR_BUILD_MODULES})
    string(TOUPPER "${module}" upper_module)
    set(SR_BUILD_MODULE_${upper_module} 1)
endforeach()

set(ALL_ARCHES x86 x86_64 arm arm64)
set(ARCH_SIZES 32  64     32  64)
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

if(EXISTS ${BAREFLANK_DIR})
    set(SR_PLATFORM bareflank)
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
elseif(WIN32)
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

    if (SR_BUILD_LIBELF)
        # Get the number of processors to pass to make -j
        include(ProcessorCount)
        ProcessorCount(NUM_PROCS)
        if (NOT NUM_PROCS)
            set(NUM_PROCS 1)
        endif()

        # Update these when upgrading libelf
        set(LIBELF_VERSION "0.176")
        set(LIBELF_MD5 "077e4f49320cad82bf17a997068b1db9")

        set(LIBELF_PATH ${CMAKE_BINARY_DIR}/libelf)
        include(ExternalProject)
        ExternalProject_Add(sr_libelf_build
            PREFIX ${LIBELF_PATH}
            URL http://deb.debian.org/debian/pool/main/e/elfutils/elfutils_${LIBELF_VERSION}.orig.tar.bz2
            URL_HASH MD5=${LIBELF_MD5}
            DOWNLOAD_NO_PROGRESS 1
            CONFIGURE_COMMAND ${LIBELF_PATH}/src/sr_libelf_build/configure --quiet --prefix=${LIBELF_PATH}
            BUILD_COMMAND make --quiet -j${NUM_PROCS}
            INSTALL_COMMAND make --quiet install
            BUILD_BYPRODUCTS ${LIBELF_PATH}/src/sr_libelf_build-build/libelf/libelf.a
            )

        # Can't use find_library() here since it's not compatible with
        # ExternalProject, so add libelf.a as an imported library
        include_directories(${LIBELF_PATH} ${LIBELF_PATH}/include)
        add_library(sr_libelf STATIC IMPORTED)
        set_target_properties(sr_libelf PROPERTIES IMPORTED_LOCATION ${LIBELF_PATH}/src/sr_libelf_build-build/libelf/libelf.a)
        add_dependencies(sr_libelf sr_libelf_build)
        set(SR_LIBELF_LIB sr_libelf)
        set(SR_LIBELF_TARGET sr_libelf_build)
    else()
        if (LIBELF_PATH)
            include_directories(${LIBELF_PATH} ${LIBELF_PATH}/include)
        endif()
        find_library(SR_LIBELF_LIB
            libelf.a
            HINTS "${LIBELF_PATH}"
            PATH_SUFFIXES bin lib
            )
    endif()
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
if("${CMAKE_SYSTEM_NAME}" STREQUAL "Android")
    add_definitions(-DRANDOLIB_IS_ANDROID=1)
endif()

add_subdirectory(src)
