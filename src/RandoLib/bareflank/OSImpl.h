/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2018 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#ifndef __RANDOLIB_OSLINUX_H
#define __RANDOLIB_OSLINUX_H
#pragma once

#ifdef __cplusplus
extern "C" {
void *platform_memset(void*, char, uint64_t);
void *platform_memcpy(void*, const void*, uint64_t);
// TODO: platform_random???
// TODO: platform_config???
}

namespace os {

typedef uint8_t *BytePointer;
typedef uint64_t Time;
typedef int File;
typedef int Pid;

static const File kInvalidFile = -1;

class APIImpl : public APIBase {
public:
    template<typename... Args>
    static void SystemMessage(const char *fmt, Args... args) {
        _TRaP_bfdebug(fmt, args...);
    }


    static inline void memcpy(void *dst, const void *src, size_t size) {
        platform_memcpy(dst, src, size);
    }

    static inline int memcmp(const void *a, const void *b, size_t size) {
        // We don't call this (yet) from RandoLib.cpp, only from OS-specific
        // code on Windows
        __builtin_trap();
        return 0;
    }

    static inline void *memset(void *s, int c, size_t n) {
        return platform_memset(s, c, n);
    }

    static inline size_t random(size_t max) {
        // TODO: call platform_random()
        return 0x1337 % max;
    }

    static inline Time time() {
        __builtin_trap();
        return 0;
    }

    static inline unsigned long long usec_between(const Time &from, const Time &to) {
        return to - from; // FIXME
    }

    static char *getenv(const char *var) {
        // TODO: call platform_config()
        return nullptr;
    }

    static Pid getpid() {
        __builtin_trap();
        return 0;
    }

    // TODO: make this into a compile-time value,
    // or maybe a run-time one, and also a TRaP
    // info setting
    static const int kFunctionP2Align = 2;
    static const int kTextAlignment = 4096;
    static const int kPageAlignment = 4096;
    static const bool kPreserveFunctionOffset = true;

    static bool is_one_byte_nop(BytePointer);
    static void insert_nops(BytePointer, size_t);

protected:
    static void debug_printf_impl(const char *fmt, ...);
};

}
#endif // __cplusplus

#endif // __RANDOLIB_OSLINUX_H
