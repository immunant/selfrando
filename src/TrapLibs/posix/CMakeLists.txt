
cmake_policy(SET CMP0063 NEW)

if (SR_BUILD_MODULE_TRAPLIBS)
    # Make stack non-executable in assembly files
    add_compile_options(-Wa,--noexecstack)

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

    # Create the entry libraries
    # Build the trapheader/footer objects
    add_library(trapheader        STATIC TrapHeader.S)
    add_library(trapheader_page   STATIC TrapHeaderPage.S)
    add_library(trapfooter        STATIC TrapFooter.S)
    add_library(trapfooter_page   STATIC
        ${SR_ARCH}/TrapFooterFiller.S
        ${SR_ARCH}/TrapFooterPage.S)
    add_library(trapfooter_nopage STATIC TrapFooterNoPage.S)

    set(static_libs
        trapheader
        trapheader_page
        trapfooter
        trapfooter_page
        trapfooter_nopage
        )
    install(TARGETS
        ${static_libs}
        DESTINATION bin/${SR_ARCH}
        )
endif()
