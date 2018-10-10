
cmake_policy(SET CMP0063 NEW)

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

    add_library(selfrando_objects OBJECT
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

    # Add dependency on libelf since we import ELF headers
    if (SR_LIBELF_TARGET)
        add_dependencies(selfrando_objects ${SR_LIBELF_TARGET})
    endif()

    add_library(selfrando_noprefix STATIC $<TARGET_OBJECTS:selfrando_objects>)

    # Build libselfrando.a with .selfrando prefix prepended to all sections
    add_custom_target(libselfrando.a ALL
        COMMAND ${CMAKE_OBJCOPY} --prefix-alloc-sections=.selfrando libselfrando_noprefix.a libselfrando.a
        COMMAND ${CMAKE_OBJCOPY} --rename-section .selfrando.eh_frame=.eh_frame libselfrando.a
        COMMAND ${CMAKE_OBJCOPY} --prefix-symbols=_TRaP_ libselfrando.a
        COMMAND ${CMAKE_OBJCOPY} --redefine-syms=${CMAKE_CURRENT_SOURCE_DIR}/non_trap_syms.txt libselfrando.a
        # TODO: add _TRaP_environ to non_trap_syms???
        COMMAND ${CMAKE_OBJCOPY} --redefine-sym=_TRaP_environ=environ libselfrando.a
        VERBATIM
        )
    add_dependencies(libselfrando.a selfrando_noprefix)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/libselfrando.a
        DESTINATION bin/${SR_ARCH})

endif()
