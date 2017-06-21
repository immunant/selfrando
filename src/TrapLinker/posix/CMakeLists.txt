
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
        #FIXME: add them back in when they compile
        #arch/arm/ELF.cpp
        #arch/arm64/ELF.cpp
        arch/x86/ELF.cpp
        arch/x86_64/ELF.cpp
        LinkerOptions.inc
        )

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

    add_custom_command(TARGET traplinker
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E create_symlink traplinker ld
        COMMAND ${CMAKE_COMMAND} -E create_symlink traplinker ld.bfd
        COMMAND ${CMAKE_COMMAND} -E create_symlink traplinker ld.gold
        BYPRODUCTS ld ld.bfd ld.gold
        VERBATIM
        COMMENT "Creating ld symlinks"
        )

    add_dependencies(traplinker randolib_support ${SR_LIBELF_TARGET})

    install(TARGETS traplinker DESTINATION bin)
    install(PROGRAMS
        ${CMAKE_CURRENT_BINARY_DIR}/ld
        ${CMAKE_CURRENT_BINARY_DIR}/ld.bfd
        ${CMAKE_CURRENT_BINARY_DIR}/ld.gold
        linker_id.sh
        DESTINATION bin
        )
    install(FILES
        linker_script.ld
        provide_TRaP_end_page.ld
        DESTINATION bin
        )
endif()
