
cmake_policy(SET CMP0063 NEW)

set(SR_RNG "chacha" CACHE STRING
    "Random number generator to use ('chacha', 'rand_r' or 'urandom')")
set(SR_NO_MREMAP OFF CACHE BOOL
    "Avoid using mremap() to rallocate memory")
set(SR_HOOK_PREINIT ON CACHE BOOL
    "Hook .preinit_array to perform randomization before all other initializers")
set(SR_RANDOLIB_BUILD_SHARED ON CACHE BOOL "Build libselfrando as a shared library")
set(SR_RANDOLIB_BUILD_STATIC ON CACHE BOOL "Build libselfrando as a static library")
set(SR_RANDOLIB_BUILD_OBJECT ON CACHE BOOL "Build selfrando_txtrp.o as a static object")

set(ALLOWED_RNGS chacha rand_r urandom)
set_property(CACHE SR_RNG PROPERTY STRINGS ${ALLOWED_RNGS})
list(FIND ALLOWED_RNGS ${SR_RNG} rng_idx)
if(${rng_idx} LESS 0)
    message(FATAL_ERROR "Unknown RNG '${SR_RNG}'!")
endif()
string(TOUPPER ${SR_RNG} upper_rng)
add_definitions(-DRANDOLIB_RNG_IS_${upper_rng}=1)

if (SR_BUILD_MODULE_RANDOLIB)
    # Make stack non-executable in assembly files
    add_compile_options(-Wa,--noexecstack)

    # We don't want to depend on memset/memcpy/the rest
    if ("${SR_ARCH}" STREQUAL "x86" OR "${SR_ARCH}" STREQUAL "x86_64")
        add_compile_options(-minline-all-stringops)
    endif()

    add_compile_options(-fno-exceptions)

    # Since we're trying to avoid depending on glibc,
    # we have to disable the stack protector
    add_compile_options(-fno-stack-protector)

    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
    set(CMAKE_C_VISIBILITY_PRESET hidden)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_ASM_VISIBILITY_PRESET hidden)

    if("${SR_ARCH}" STREQUAL "x86")
        add_compile_options(-m32)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
    endif()

    if(SR_HOOK_PREINIT)
        set(preinit_entry_file ${SR_ARCH}/PreinitEntryPoint.S)
    endif()

    # Create the entry libraries
    set(entry_files
        ${SR_ARCH}/EntryPointWrapper.S
        ${SR_ARCH}/Textramp.S
        EntryPoint.c)
    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Android")
        list(APPEND entry_files ${SR_ARCH}/AndroidInit.c)
    endif()
    if("${SR_ARCH}" STREQUAL "arm")
        list(APPEND entry_files arm/LinkerStubs.S)
        # We need _TRaP_memset on ARM to avoid a dependency on libgcc
        list(APPEND entry_files bionic/arch-arm/memset.S)
    endif()
    add_library(randoentry_exec STATIC ${entry_files} EntryPointExec.c
        ${preinit_entry_file})
    add_library(randoentry_so   STATIC ${entry_files} EntryPointSO.c)

    # Ensure that we don't emit unwind tables to avoid depending on the libgcc
    # provided personality functions
    set_target_properties(randoentry_exec PROPERTIES COMPILE_FLAGS "-fno-unwind-tables")
    set_target_properties(randoentry_so PROPERTIES COMPILE_FLAGS "-fno-unwind-tables")
    target_compile_definitions(randoentry_so PRIVATE -DNOUNWIND)
    target_compile_definitions(randoentry_exec PRIVATE -DNOUNWIND)

    if("${SR_ARCH}" STREQUAL "arm")
        # On ARM, memset.S requires bionic/private/bionic_asm.h
        target_include_directories(randoentry_exec PRIVATE bionic bionic/arch-arm)
        target_include_directories(randoentry_so   PRIVATE bionic bionic/arch-arm)
    endif()

    set(static_libs
        randoentry_exec
        randoentry_so
        )
    foreach(static_lib ${static_libs})
        add_custom_command(TARGET ${static_lib}
            POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} --rename-section .text.__x86.get_pc_thunk.bx=.selfrando.text.__x86.get_pc_thunk.bx $<TARGET_FILE:${static_lib}>
            COMMAND ${CMAKE_OBJCOPY} --rename-section .text.selfrando__x86.get_pc_thunk.bx=.text.__x86.get_pc_thunk.bx $<TARGET_FILE:${static_lib}>
            COMMAND ${CMAKE_OBJCOPY} --prefix-symbols=_TRaP_ $<TARGET_FILE:${static_lib}>
            COMMAND ${CMAKE_OBJCOPY} --redefine-syms=${CMAKE_CURRENT_SOURCE_DIR}/non_trap_syms.txt $<TARGET_FILE:${static_lib}>
            # On 32-bit x86, we need __x86.get_pc_thunk.bx to be defined as the
            # compiler emits it: a single-element group section
            # FIXME: it would be nice to get rid of this
            COMMAND ${CMAKE_OBJCOPY} --redefine-sym=_TRaP_selfrando__x86.get_pc_thunk.bx=__x86.get_pc_thunk.bx $<TARGET_FILE:${static_lib}>
            VERBATIM
            )
    endforeach()
    install(TARGETS
        ${static_libs}
        DESTINATION bin/${SR_ARCH}
        )

    set(selfrando_sources
        ../RandoLib.cpp
        OSImpl.cpp
        ../util/hash_32a.c
        ../util/strtol.c
        ../util/qsort.c
        ../util/printf.cpp
        ../arch/${SR_ARCH}/Util.cpp
        ${SR_ARCH}/Relocation.cpp
        ${SR_ARCH}/Cache.cpp
        )

    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Android" AND "${SR_ARCH}" STREQUAL "arm")
        list(APPEND selfrando_sources arm/UnwindStubs.c)
    endif()

    if("${SR_RNG}" STREQUAL "chacha")
        list(APPEND selfrando_sources ../util/rand_chacha.cpp)
    elseif("${SR_RNG}" STREQUAL "urandom")
        list(APPEND selfrando_sources util/rand_linux.cpp)
    endif()

    if(SR_NO_MREMAP)
        add_definitions(-DRANDOLIB_NO_MREMAP=1)
    endif()

    include(bionic/CMakeLists.txt)

    # TODO: include all the Android options

    ### Build libselfrando.so
    if(SR_RANDOLIB_BUILD_SHARED)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++ -nostdlib")
        add_library(selfrando SHARED ${selfrando_sources})
        target_link_libraries(selfrando PRIVATE dl gcc)
        target_compile_definitions(selfrando PRIVATE -DRANDOLIB_IS_SHARED=1)
        if (SR_LIBELF_TARGET)
            # Add dependency on libelf since we import ELF headers
            add_dependencies(selfrando ${SR_LIBELF_TARGET})
        endif()
        if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Android")
            # Android doesn't provide libgcc_eh.a
            target_link_libraries(selfrando PRIVATE gcc_eh)
        endif()
        install(TARGETS selfrando DESTINATION bin/${SR_ARCH})
    endif()

    ### Build libselfrando.a and selfrando_txtrp.o
    if(SR_RANDOLIB_BUILD_STATIC OR SR_RANDOLIB_BUILD_OBJECT)
        add_library(selfrando_static_noprefix STATIC ${selfrando_sources})

        if (SR_LIBELF_TARGET)
            # Add dependency on libelf since we import ELF headers
            add_dependencies(selfrando_static_noprefix ${SR_LIBELF_TARGET})
        endif()

        if(SR_RANDOLIB_BUILD_STATIC)
            # Build libselfrando.a with .selfrando prefix prepended to all sections
            add_custom_target(selfrando_static ALL
                COMMAND ${CMAKE_OBJCOPY} --prefix-alloc-sections=.selfrando libselfrando_static_noprefix.a libselfrando.a
                COMMAND ${CMAKE_OBJCOPY} --rename-section .selfrando.eh_frame=.eh_frame libselfrando.a
                COMMAND ${CMAKE_OBJCOPY} --prefix-symbols=_TRaP_ libselfrando.a
                COMMAND ${CMAKE_OBJCOPY} --redefine-syms=${CMAKE_CURRENT_SOURCE_DIR}/non_trap_syms.txt libselfrando.a
                # TODO: add _TRaP_environ to non_trap_syms???
                COMMAND ${CMAKE_OBJCOPY} --redefine-sym=_TRaP_environ=environ libselfrando.a
                VERBATIM
                )
            add_dependencies(selfrando_static selfrando_static_noprefix)
            install(FILES
                ${CMAKE_CURRENT_BINARY_DIR}/libselfrando.a
                DESTINATION bin/${SR_ARCH})
        endif()

        if(SR_RANDOLIB_BUILD_OBJECT)
            # Build selfrando_txtrp.o with all the code in .txtrp
            # FIXME: is this list correct?
            add_custom_target(selfrando_txtrp.o ALL
                COMMAND env "OBJCOPY=${CMAKE_OBJCOPY}" "OBJDUMP=${CMAKE_OBJDUMP}"
                ${CMAKE_CURRENT_SOURCE_DIR}/rename_sections_txtrp.sh
                libselfrando_static_noprefix.a
                selfrando_txtrp.o
                COMMAND ${CMAKE_OBJCOPY} --prefix-symbols=_TRaP_ selfrando_txtrp.o
                COMMAND ${CMAKE_OBJCOPY} --redefine-syms=${CMAKE_CURRENT_SOURCE_DIR}/non_trap_syms.txt selfrando_txtrp.o
                COMMAND ${CMAKE_OBJCOPY} --redefine-sym=_TRaP_environ=environ selfrando_txtrp.o
                VERBATIM
                )
            add_dependencies(selfrando_txtrp.o selfrando_static_noprefix)
            install(FILES
                ${CMAKE_CURRENT_BINARY_DIR}/selfrando_txtrp.o
                DESTINATION bin/${SR_ARCH})
        endif()
    endif()
endif()
