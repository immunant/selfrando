
set(SR_RNG "urandom" CACHE STRING
    "Random number generator to use ('rand_r' or 'urandom')")

set(ALL_RNGS rand_r urandom)
list(FIND ALL_RNGS ${SR_RNG} rng_idx)
if(${rng_idx} LESS 0)
    message(FATAL_ERROR "Unknown RNG '${SR_RNG}'!")
endif()
string(TOUPPER ${SR_RNG} upper_rng)
add_definitions(-DRANDOLIB_RNG_IS_${upper_rng}=1)

include_directories(
    ${CMAKE_SOURCE_DIR}/src/TrapInfo
    ${CMAKE_SOURCE_DIR}/src/RandoLib
    )

# Make stack non-executable in assembly files
add_compile_options(-Wa,--noexecstack)
add_compile_options(-m${SR_ARCH_SIZE})
add_compile_options(-fPIC)
add_compile_options(-fvisibility=hidden)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility-inlines-hidden")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack")

# Create the entry libraries
set(entry_files
    ${SR_ARCH}/EntryPointWrapper.S
    ${SR_ARCH}/Textramp.S
    EntryPoint.c)
if(ANDROID_NDK)
    list(APPEND entry_files ${SR_ARCH}/AndroidInit.c)
endif()
if("${SR_ARCH}" STREQUAL "arm")
    list(APPEND entry_files arm/LinkerStubs.S)
endif()
add_library(randoentry_exec STATIC ${entry_files} EntryPointExec.c)
add_library(randoentry_so   STATIC ${entry_files} EntryPointSO.c)

# Build the trapheader/footer objects
add_library(trapheader      STATIC TrapHeader.S)
add_library(trapheader_page STATIC TrapHeader.S)
add_library(trapfooter      STATIC TrapFooter.S)
add_library(trapfooter_page STATIC TrapFooterPage.S)
target_compile_definitions(trapheader      PRIVATE -DTXTRP_ALIGNMENT=1)
target_compile_definitions(trapheader_page PRIVATE -DTXTRP_ALIGNMENT=4096)

add_library(selfrando_objects OBJECT
    ../RandoLib.cpp
    ../OS.h
    OSImpl.cpp
    OSImpl.h
    ../util/hash_32a.c
    ../util/strtol.c
    ../util/qsort.c
    ../util/printf.cpp
    ../arch/${SR_ARCH}/Util.cpp
    ${SR_ARCH}/Relocation.cpp
    ${SR_ARCH}/Cache.cpp
    )

if(${SR_RNG} STREQUAL "urandom")
    target_sources(selfrando_objects PRIVATE util/rand_linux.cpp)
endif()

include(bionic/CMakeLists.txt)

# TODO: include all the Android options

# FIXME: scons can build both a shared and static library
# from the same source files but with different C defs
# but that's not as simple with cmake
if(BUILD_SHARED_LIBS)
    target_compile_definitions(selfrando_objects PRIVATE -DRANDOLIB_IS_SHARED=1)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++ -nostdlib")
    add_library(selfrando SHARED $<TARGET_OBJECTS:selfrando_objects>)
    target_link_libraries(selfrando PRIVATE dl)
    install(TARGETS selfrando DESTINATION bin)
else()
    add_library(selfrando_noprefix STATIC $<TARGET_OBJECTS:selfrando_objects>)

    # Build libselfrando.a with .selfrando prefix prepended to all sections
    add_custom_target(libselfrando.a ALL
        COMMAND objcopy --prefix-alloc-sections=.selfrando libselfrando_noprefix.a libselfrando.a
        COMMAND objcopy --rename-section .selfrando.eh_frame=.eh_frame libselfrando.a
        VERBATIM
        )

    # Build selfrando_txtrp.o with all the code in .txtrp
    # FIXME: is this list correct?
    set(ALL_LDEMULS elf_i386 elf_x86_64 armelf aarch64linux)
    list(FIND ALL_ARCHES ${SR_ARCH} arch_idx)
    list(GET ALL_LDEMULS ${arch_idx} arch_ldemul)
    add_custom_target(selfrando_txtrp.o ALL
        COMMAND ${CMAKE_LINKER} -r -m ${arch_ldemul} -o selfrando_txtrp.o
            -T${CMAKE_CURRENT_SOURCE_DIR}/selfrando_txtrp.ld
            --whole-archive libselfrando_noprefix.a
        VERBATIM
        )

    add_dependencies(libselfrando.a selfrando_noprefix)
    add_dependencies(selfrando_txtrp.o selfrando_noprefix)

    install(TARGETS libselfrando.a selfrando_txtrp.o DESTINATION bin)
endif()

install(TARGETS
    trapheader
    trapheader_page
    trapfooter
    trapfooter_page
    DESTINATION bin
    )
