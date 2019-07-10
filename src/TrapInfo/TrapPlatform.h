/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

typedef enum {
    TRAP_PLATFORM_UNKNOWN = 0,
    TRAP_PLATFORM_POSIX_X86,
    TRAP_PLATFORM_POSIX_X86_64,
    TRAP_PLATFORM_POSIX_ARM,
    TRAP_PLATFORM_POSIX_ARM64,
    TRAP_PLATFORM_WIN32,
    TRAP_PLATFORM_WIN64,
} trap_platform_t;

// Define TRAP_CURRENT_PLATFORM
// FIXME: we should get rid of this
#if RANDOLIB_IS_POSIX || RANDOLIB_IS_BAREFLANK
#if RANDOLIB_IS_X86
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_POSIX_X86
#elif RANDOLIB_IS_X86_64
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_POSIX_X86_64
#elif RANDOLIB_IS_ARM
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_POSIX_ARM
#elif RANDOLIB_IS_ARM64
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_POSIX_ARM64
#else
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_UNKNOWN
#endif
#elif RANDOLIB_IS_WIN32
#if RANDOLIB_IS_X86
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_WIN32
#elif RANDOLIB_IS_X86_64
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_WIN64
#else
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_UNKNOWN
#endif
#else
#define TRAP_CURRENT_PLATFORM  TRAP_PLATFORM_UNKNOWN
#endif

#ifndef RANDO_SECTION
#define RANDO_SECTION
#endif

static inline RANDO_SECTION
uint64_t trap_platform_pointer_size(trap_platform_t platform) {
    switch (platform) {
    case TRAP_PLATFORM_POSIX_X86:
    case TRAP_PLATFORM_POSIX_ARM:
    case TRAP_PLATFORM_WIN32:
        return 32;

    case TRAP_PLATFORM_POSIX_X86_64:
    case TRAP_PLATFORM_POSIX_ARM64:
    case TRAP_PLATFORM_WIN64:
        return 64;

    default:
        // FIXME: do we want to assert here???
        return 8 * sizeof(void*);
    }
}
