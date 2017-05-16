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

    // Debugging functions and settings
#if RANDOLIB_DEBUG_LEVEL_IS_ENV
    static int debug_level;
#else
#ifdef RANDOLIB_DEBUG_LEVEL
    static const int debug_level = RANDOLIB_DEBUG_LEVEL;
#else
    static const int debug_level = 0;
#endif
#endif
    static const bool kEnableAsserts = true;

    template<int level, typename... Args>
    static inline void DebugPrintf(Args... args) {
        // FIXME: this should use std::forward, but can we pull in <utility>???
        if (level <= debug_level)
            DebugPrintfImpl(args...);
    }

    // Explicitly list functions inherited from APIImpl, so compilation fails if they're missing
    using APIImpl::QuickSort;
    using APIImpl::MemCpy;
    using APIImpl::MemCmp;
    using APIImpl::GetRandom;
    using APIImpl::GetTime;
    using APIImpl::GetEnv;
    using APIImpl::GetPid;
    using APIImpl::TimeDeltaMicroSec;
    using APIImpl::DebugPrintfImpl;

    // Architecture-specific functions/constants
    using APIImpl::Is1ByteNOP;
    using APIImpl::InsertNOPs;

    // Align function addresses to multiples of this values
    using APIImpl::kFunctionP2Align;

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
    static void *MemReAlloc(void*, size_t, bool zeroed = false);
    static void MemFree(void*);
    static void *MemMap(void*, size_t, PagePermissions, bool); // TODO
    static void MemUnmap(void*, size_t, bool); // TODO
    static PagePermissions MemProtect(void*, size_t, PagePermissions);

    static File OpenFile(const char *name, bool write, bool create);
    static ssize_t WriteFile(File file, const void *buf, size_t len);
    static void CloseFile(File file);

#if RANDOLIB_WRITE_LAYOUTS > 0
    static File OpenLayoutFile(bool write);
#endif
};

struct SortTask {
    typedef int(*CompareFunc)(const void*, const void*);

    SortTask() = delete;
    SortTask(void *base, size_t num, size_t size, CompareFunc cmp)
        : m_base(base), m_num(num), m_size(size), m_cmp(cmp) {
    }

    void run() const {
        API::QuickSort(m_base, m_num, m_size, m_cmp);
    }

private:
    void *m_base;
    size_t m_num;
    size_t m_size;
    CompareFunc m_cmp;
};

}

#if RANDOLIB_IS_WIN32
#include "win32/OSModule.h"
#elif RANDOLIB_IS_POSIX
#include "posix/OSModule.h"
#else
#error "Unrecognized OS"
#endif

#endif  // __cplusplus

#endif // __RANDOLIB_OS_H
