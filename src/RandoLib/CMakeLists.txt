
set(SR_LOG "default" CACHE STRING
    "Logging to perform ('default', 'none', 'console', 'file', 'system')")
set(SR_LOG_FILENAME "/tmp/selfrando.log" CACHE STRING
    "Log file to output to")
set(SR_LOG_APPEND OFF CACHE BOOL
    "Append to log instead of replacing it")
set(SR_DEBUG_SEED "" CACHE STRING
    "Fixed seed to use for debugging")
set(SR_FORCE_INPLACE OFF CACHE BOOL
    "Terminate execution (via failed assertion) if in-place randomization would fail")
set(SR_WRITE_LAYOUTS "no" CACHE STRING
    "After randomization, write layout files to /tmp/ (set to 'no', 'env' or 'always')")

# TODO: notify cmake about the options, so they show up in the GUI
set(ALLOWED_LOG default none console file system)
list(FIND ALLOWED_LOG ${SR_LOG} log_idx)
if(log_idx LESS 0)
    message(FATAL_ERROR "Unknown logging method: '${SR_LOG}'!")
endif()
string(TOUPPER ${SR_LOG} upper_log)
add_definitions(-DRANDOLIB_LOG_TO_${upper_log}=1)
add_definitions(-DRANDOLIB_LOG_FILENAME="${SR_LOG_FILENAME}")

if(SR_LOG_APPEND)
    # FIXME: this would be cleaner with a configure'd header
    add_definitions(-DRANDOLIB_LOG_APPEND=1)
endif()

if(SR_DEBUG_SEED)
    # FIXME: this would be cleaner with a configure'd header
    add_definitions(-DRANDOLIB_DEBUG_SEED=${SR_DEBUG_SEED})
endif()

if(SR_FORCE_INPLACE)
    # FIXME: this would be cleaner with a configure'd header
    add_definitions(-DRANDOLIB_FORCE_INPLACE=1)
endif()

# TODO: notify cmake about the options, so they show up in the GUI
set(ALLOWED_WRITE_LAYOUTS no env always)
list(FIND ALLOWED_WRITE_LAYOUTS ${SR_WRITE_LAYOUTS} write_layouts_idx)
if(${write_layouts_idx} LESS 0)
    message(FATAL_ERROR "Unknown option for SR_WRITE_LAYOUTS: '${SR_WRITE_LAYOUTS}'!")
endif()
add_definitions(-DRANDOLIB_WRITE_LAYOUTS=${write_layouts_idx})

add_subdirectory(${SR_PLATFORM})
