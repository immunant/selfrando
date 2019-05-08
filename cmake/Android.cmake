# CMake Android toolchain file for selfrando
#
# Invoke it using:
# $ cmake -DCMAKE_TOOLCHAIN_FILE=cmake/Android.cmake -DCMAKE_ANDROID_NDK=<path to NDK> -DSR_ARCH=<...>
# or
# $ SR_ARCH=<...> ./scripts/build_cmake.sh -DCMAKE_TOOLCHAIN_FILE=cmake/Android.cmake -DCMAKE_ANDROID_NDK=<path to NDK>

set(CMAKE_SYSTEM_NAME Android)

set(SR_ARCH "arm" CACHE STRING "Target architecture for Android")
set(ALL_ARCHES x86 x86_64 arm     arm64)
set(ARCH_ABIS  x86 x86_64 armeabi-v7a arm64-v8a)
list(FIND ALL_ARCHES ${SR_ARCH} arch_idx)
if(arch_idx LESS 0)
    message(FATAL_ERROR "Unknown architecture '${SR_ARCH}', "
                        "must be one of '${ALL_ARCHES}'!")
endif()
list(GET ARCH_ABIS ${arch_idx} arch_abi)
set(CMAKE_ANDROID_ARCH_ABI ${arch_abi})

# When building for Android, only build RandoLib
set(SR_BUILD_MODULES "RandoLib;TrapLibs" CACHE STRING "Selfrando modules to build for Android")

# CMake doesn't set up the system include directories for ASM by default, so we
# need to do that.
include(Platform/Android-Common)
__android_compiler_common(ASM)
