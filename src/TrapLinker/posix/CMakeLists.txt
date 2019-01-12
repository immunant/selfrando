
set(TRAPLINKER_INSTALL_LD ON CACHE BOOL
    "Install ld replacement links")
set(TRAPLINKER_KEEP_FILES OFF CACHE BOOL
    "Keep temporary files produced by TrapLinker")
set(TRAPLINKER_DEBUG_ASAN OFF CACHE BOOL
    "Build TrapLinker with ASAN (for debugging)")

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/src/TrapInfo
    ${CMAKE_SOURCE_DIR}/src/TrapLinker
    ${CMAKE_SOURCE_DIR}/src/Support
    ${CMAKE_SOURCE_DIR}/src/Support/posix
    )

if (SR_BUILD_MODULE_TRAPLINKER)
    add_executable(traplinker
        ELF.cpp
        TrapLinker.cpp
        arch/x86/ELF.cpp
        arch/x86_64/ELF.cpp
        arch/arm/ELF.cpp
        arch/arm64/ELF.cpp
        LinkerOptions.inc
        )

    if (TRAPLINKER_KEEP_FILES)
        add_definitions(-DTRAPLINKER_KEEP_FILES)
    endif()

    if (TRAPLINKER_DEBUG_ASAN)
        target_compile_options(traplinker PRIVATE
            -fsanitize=address
            -fno-omit-frame-pointer
            -fno-optimize-sibling-calls
            )
        target_link_libraries(traplinker
            -fsanitize=address
            -fno-omit-frame-pointer
            )
    endif()

    target_link_libraries(traplinker ${SR_LIBELF_LIB} z randolib_support)
    target_compile_options(traplinker PRIVATE -static)

    add_custom_command(
        OUTPUT LinkerOptions.inc
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gen_options.py
            LinkerOptions.inc
            "${CMAKE_CURRENT_SOURCE_DIR}/LinkerOptions.table"
            "${CMAKE_CURRENT_SOURCE_DIR}/IgnoredOptions.table"
        DEPENDS LinkerOptions.table IgnoredOptions.table
        VERBATIM
        COMMENT "Generate linker options table"
        )

    add_dependencies(traplinker randolib_support ${SR_LIBELF_TARGET})

    install(TARGETS traplinker DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(PROGRAMS
        traplinker_id.sh
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    install(FILES
        traplinker_script.ld
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

    if (TRAPLINKER_INSTALL_LD)
        add_custom_command(TARGET traplinker
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E create_symlink traplinker ld
            COMMAND ${CMAKE_COMMAND} -E create_symlink traplinker ld.bfd
            COMMAND ${CMAKE_COMMAND} -E create_symlink traplinker ld.gold
            BYPRODUCTS ld ld.bfd ld.gold
            VERBATIM
            COMMENT "Creating ld symlinks"
            )

        install(PROGRAMS
            ${CMAKE_CURRENT_BINARY_DIR}/ld
            ${CMAKE_CURRENT_BINARY_DIR}/ld.bfd
            ${CMAKE_CURRENT_BINARY_DIR}/ld.gold
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            )
    endif()
endif()
