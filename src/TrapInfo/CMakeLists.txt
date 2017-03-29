
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(trapdump
    TrapDump.c
    ${SR_PLATFORM}/ReadTrap.c
    TrapInfo.h
    TrapInfoRelocs.h
    )

if(UNIX)
target_link_libraries(trapdump elf)
endif()

install(TARGETS trapdump DESTINATION bin)
