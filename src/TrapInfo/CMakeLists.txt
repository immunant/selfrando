
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(trapdump
    TrapDump.c
    ${SR_PLATFORM}/ReadTrap.c
    )

if(UNIX)
    target_link_libraries(trapdump ${SR_LIBELF_LIB} z)
endif()

install(TARGETS trapdump DESTINATION bin)
