/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#ifndef __RANDOLIB_OS_H
#define __RANDOLIB_OS_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

namespace os {

static const size_t kPageSize = 4096;

enum class PagePermissions : uint8_t {
    NONE = 0,
    R    = 1,
    W    = 2,
    RW   = 3,
    X    = 4,
    RX   = 5,
    WX   = 6,
    RWX  = 7,

    // Return UNKNOWN when permissions cannot be determined
    UNKNOWN = 255,
};

// Addresses inside the binary may use different address spaces, e.g.,
// some addresses inside PE binaries on Windows may be absolute, while
// others are RVAs (relative to the program base).
enum class AddressSpace : uint8_t {
    MEMORY = 0,           // Absolute memory addresses
    TRAP,                 // Address space used by addresses inside Trap info
    RVA,                  // Windows-specific: address relative to the image base
};

}

#if defined(WIN32)
#include "win32/OSImpl.h"
#elif defined(linux) || defined(__linux__) || defined(LINUX)
#include "posix/OSImpl.h"
#else
#error "Unrecognized OS"
#endif

namespace os {

class RANDO_SECTION API : public APIImpl {
public:
    static void Init();
    static void Finish();

    // Explicitly list functions inherited from APIImpl, so compilation fails if they're missing
    using APIImpl::QuickSort;
    using APIImpl::MemCpy;
    using APIImpl::MemCmp;
    using APIImpl::GetRandom;
    using APIImpl::GetTime;
    using APIImpl::TimeDeltaMicroSec;
    using APIImpl::DebugPrintf;

    static void *MemAlloc(size_t, bool zeroed = false);
    static void MemFree(void*);
    static void *MemMap(void*, size_t, PagePermissions, bool); // TODO
    static void MemUnmap(void*, size_t, bool); // TODO
    static PagePermissions MemProtect(void*, size_t, PagePermissions);
};

}

#endif // __RANDOLIB_OS_H
