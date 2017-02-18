/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#ifndef __RANDOLIB_OS_H
#define __RANDOLIB_OS_H
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
namespace os {

static const size_t kPageShift = 12;
static const size_t kPageSize = (1 << kPageShift);

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
#endif // __cplusplus

#if RANDOLIB_IS_WIN32
#include "win32/OSImpl.h"
#elif RANDOLIB_IS_POSIX
#include "posix/OSImpl.h"
#else
#error "Unrecognized OS"
#endif

#ifdef __cplusplus
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
    using APIImpl::GetEnv;
    using APIImpl::TimeDeltaMicroSec;
    using APIImpl::DebugPrintf;

    // Architecture-specific functions/constants
    using APIImpl::InsertNOPs;

    // Align function addresses to multiples of this values
    using APIImpl::kFunctionAlignment;

    // Preserve function alignment offsets past randomization
    // If this is true and a function at address A before randomization
    // such that A % kFunctionAlignment == O (offset), then the
    // randomization library will also place it at some address A'
    // such that A' % kFunctionAlignment == O. To put it another way:
    // A === A' (mod kFunctionAlignment)
    // If this is false, the address of each function will always be a multiple
    // of kFunctionAlignment after randomization
    using APIImpl::kPreserveFunctionOffset;

    static void *MemAlloc(size_t, bool zeroed = false);
    static void MemFree(void*);
    static void *MemMap(void*, size_t, PagePermissions, bool); // TODO
    static void MemUnmap(void*, size_t, bool); // TODO
    static PagePermissions MemProtect(void*, size_t, PagePermissions);
};

}
#endif  // __cplusplus

#endif // __RANDOLIB_OS_H
