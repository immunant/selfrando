/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#ifndef __RANDOLIB_OSLINUX_H
#define __RANDOLIB_OSLINUX_H
#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <link.h>

#ifdef __cplusplus
// Found in posix/qsort.c
extern "C" {
time_t _TRaP_libc_time(time_t*);
extern void *_TRaP_libc_memcpy(void *__restrict, const void *__restrict, size_t);
extern int _TRaP_libc_memcmp(const void*, const void*, size_t);
extern void *_TRaP_libc_memset(void *, int, size_t);
extern char *_TRaP_libc_getenv(const char*);
extern long _TRaP_libc_strtol(const char*, char **, int);
#if RANDOLIB_RNG_IS_RAND_R
int _TRaP_libc_rand_r(unsigned int*);
#elif RANDOLIB_RNG_IS_URANDOM
long _TRaP_rand_linux(long);
#endif
pid_t _TRaP_syscall___getpid(void);
int _TRaP_syscall_open(const char*, int, ...);
ssize_t _TRaP_syscall_write(int, const void*, size_t);
int _TRaP_syscall____close(int);
}

namespace os {

typedef uint8_t *BytePointer;
typedef time_t Time;
typedef int File;
typedef pid_t Pid;

static const File kInvalidFile = -1;

class APIImpl : public APIBase {
public:
    static void SystemMessage(const char *fmt, ...);

    static inline void memcpy(void *dst, const void *src, size_t size) {
        _TRaP_libc_memcpy(dst, src, size);
    }

    static inline int memcmp(const void *a, const void *b, size_t size) {
        return _TRaP_libc_memcmp(a, b, size);
    }

    static inline void *memset(void *s, int c, size_t n) {
        return _TRaP_libc_memset(s, c, n);
    }

    static inline size_t random(size_t max) {
#if RANDOLIB_RNG_IS_RAND_R
#if RANDOLIB_IS_ARM
        // On some architectures, we want to avoid the division below
        // because it's implemented in libgcc.so
        auto clz = (sizeof(max) == sizeof(long long)) ? __builtin_clzll(max) : __builtin_clz(max);
        auto mask = static_cast<size_t>(-1LL) >> clz;
        for (;;) {
            // Clip rand to next power of 2 after "max"
            // This ensures that we always have
            // P(rand < max) > 0.5
            auto rand = static_cast<size_t>(_TRaP_libc_rand_r(&rand_seed[0])) & mask;
            if (rand < max)
                return rand;
        }
#else
        return static_cast<size_t>(_TRaP_libc_rand_r(&rand_seed[0])) % max; // FIXME: better RNG
#endif
#elif RANDOLIB_RNG_IS_URANDOM
        return _TRaP_rand_linux(max);
#else
#error Unknown RNG setting
#endif
    }

    static inline Time time() {
        return _TRaP_libc_time(nullptr); // FIXME: we need something more precise
    }

    static inline unsigned long long usec_between(const Time &from, const Time &to) {
        return to - from; // FIXME
    }

    static char *getenv(const char *var) {
        return _TRaP_libc_getenv(var);
    }

    static Pid getpid() {
        return _TRaP_syscall___getpid();
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

    // Check if a syscall return value is an error
    // We mainly replicate what bionic does:
    // consider an error any value in [-MAX_ERRNO, 0)
    // for MAX_ERRNO == 4095 (for now)
    template<typename T>
    static inline bool syscall_retval_is_err(T retval) {
        auto ival = reinterpret_cast<intptr_t>(retval);
        return ival < 0 && ival >= -4095;
    }

protected:
    static void debug_printf_impl(const char *fmt, ...);

protected:
    static uint32_t rand_seed[RANDOLIB_SEED_WORDS];

#if RANDOLIB_LOG_TO_FILE || RANDOLIB_LOG_TO_DEFAULT
    static int log_fd;
#endif
};

}
#endif // __cplusplus

#endif // __RANDOLIB_OSLINUX_H
