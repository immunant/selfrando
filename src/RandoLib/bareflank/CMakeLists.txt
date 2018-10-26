
cmake_policy(SET CMP0063 NEW)
set(CMAKE_CXX_STANDARD 17)

if (SR_BUILD_MODULE_RANDOLIB)
    include_directories(
        ${BAREFLANK_DIR}/bfsdk/include
        ${BAREFLANK_DIR}/bfelf_loader/include
        )

    add_definitions(
        -DKERNEL
        -DNEED_GSL_LITE
        -DBF_INSIDE_SELFRANDO
        )

    if(UNIX)
        add_definitions(-DLINUX_KERNEL)

        # `and` is a C++ keyword that is also used in kernel macros,
        # which breaks compilation; we need to ask the compiler to handle it
        # like in C
        add_compile_options(-fno-operator-names)

        # Get the rest of the compiler flags from the kernel build system
        find_program(COMPILEDB compiledb)
        if("${COMPILEDB}" STREQUAL "COMPILEDB-NOTFOUND")
            message(FATAL_ERROR "compiledb not found, please install")
        endif()
        set(KERNEL_BUILD_PATH /lib/modules/${CMAKE_HOST_SYSTEM_VERSION}/build)
        if(NOT EXISTS ${KERNEL_BUILD_PATH}/Makefile)
            message(FATAL_ERROR "Kernel build files not found at ${KERNEL_BUILD_PATH}")
        endif()
        set(KERNEL_CFLAGS_DB ${CMAKE_CURRENT_BINARY_DIR}/kernel_cflags.json)
        execute_process(
            COMMAND "${COMPILEDB}" -n -o "${KERNEL_CFLAGS_DB}"
                    make -C "${KERNEL_BUILD_PATH}" modules
                        "M=${CMAKE_CURRENT_SOURCE_DIR}/linux/fakemod"
            )
        execute_process(
            COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/linux/decode_cflags.py"
                        "${KERNEL_BUILD_PATH}" "${KERNEL_CFLAGS_DB}"
            OUTPUT_VARIABLE KERNEL_CFLAGS
            )
        set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${KERNEL_CFLAGS}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${KERNEL_CFLAGS}")
    elseif(WIN32)
        add_definitions(-D_WIN32)
    endif()

    # Make stack non-executable in assembly files
    add_compile_options(-Wa,--noexecstack)

    # We don't want to depend on memset/memcpy/the rest
    if ("${SR_ARCH}" STREQUAL "x86" OR "${SR_ARCH}" STREQUAL "x86_64")
        add_compile_options(-minline-all-stringops)
    endif()

    add_compile_options(-fno-exceptions)

    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack")
    set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
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
        ../util/strtol.c
        ../util/qsort.c
        ../util/printf.cpp
        ../arch/${SR_ARCH}/Util.cpp
        ${SR_ARCH}/Relocation.cpp
        ${SR_ARCH}/Cache.cpp
        bfdebug.c
        )

    # Add dependency on libelf since we import ELF headers
    if (SR_LIBELF_TARGET)
        add_dependencies(selfrando_objects ${SR_LIBELF_TARGET})
    endif()

    add_custom_target(selfrando ALL
        COMMAND ld -r $<TARGET_OBJECTS:selfrando_objects> -o selfrando.o
        DEPENDS $<TARGET_OBJECTS:selfrando_objects>
        BYPRODUCTS selfrando.o
        COMMAND_EXPAND_LISTS
        VERBATIM
        )
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/selfrando.o
        DESTINATION bin/${SR_ARCH})

endif()
