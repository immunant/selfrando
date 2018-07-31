
set(TRAPINFO_INSTALL_HEADERS OFF CACHE BOOL
    "Install TrapInfo headers")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(SR_BUILD_MODULE_TRAPDUMP)
    add_executable(trapdump
        TrapDump.c
        ${SR_PLATFORM}/ReadTrap.c
        )

    if(UNIX)
        target_link_libraries(trapdump ${SR_LIBELF_LIB} z)
    endif()

    install(TARGETS trapdump DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(TRAPINFO_INSTALL_HEADERS)
    install(FILES
        TrapInfo.h TrapInfoRelocs.h TrapPlatform.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )
endif()
