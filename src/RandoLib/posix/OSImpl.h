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

// FIXME: gcc doesn't support assigning an entire class to a section
// so we'll either have to solve this using linker scripts
// or include RandoLib as an external shared library
#define RANDO_SECTION

#if RANDOLIB_IS_SHARED
#define RANDO_PUBLIC  __attribute__((visibility("default")))
#else
#define RANDO_PUBLIC  __attribute__((visibility("hidden")))
#endif

#define RANDO_ALWAYS_INLINE __attribute__((always_inline)) inline

#define RANDO_MAIN_FUNCTION()  extern "C" RANDO_PUBLIC void _TRaP_RandoMain(os::Module::Handle asm_module)

#ifdef __cplusplus

// Found in posix/qsort.c
extern "C" {
void _TRaP_qsort(void *, size_t, size_t,
                 int (*)(const void *, const void *));
time_t _TRaP_libc_time(time_t*);
extern void *_TRaP_libc_memcpy(void *__restrict, const void *__restrict, size_t);
extern int _TRaP_libc_memcmp(const void*, const void*, size_t);
extern char *_TRaP_libc_getenv(const char*);
extern long _TRaP_libc_strtol(const char*, char **, int);
#if RANDOLIB_RNG_IS_RAND_R
int _TRaP_libc_rand_r(unsigned int*);
#elif RANDOLIB_RNG_IS_URANDOM
long _TRaP_rand_linux(long);
#endif
pid_t _TRaP_libc___getpid(void);
int _TRaP_libc_open(const char*, int, ...);
ssize_t _TRaP_libc_write(int, const void*, size_t);
int _TRaP_libc____close(int);
}

namespace os {

typedef uint8_t *BytePointer;
typedef time_t Time;
typedef int File;
typedef pid_t Pid;

static const File kInvalidFile = -1;

class APIImpl {
public:
    static void SystemMessage(const char *fmt, ...);

    // C library functions
    static inline void qsort(void* base, size_t num, size_t size,
                             int(*cmp)(const void*, const void*)) {
        _TRaP_qsort(base, num, size, cmp);
    }

    static inline void memcpy(void *dst, const void *src, size_t size) {
        _TRaP_libc_memcpy(dst, src, size);
    }

    static inline int memcmp(const void *a, const void *b, size_t size) {
        return _TRaP_libc_memcmp(a, b, size);
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
            auto rand = static_cast<size_t>(_TRaP_libc_rand_r(&rand_seed)) & mask;
            if (rand < max)
                return rand;
        }
#else
        return static_cast<size_t>(_TRaP_libc_rand_r(&rand_seed)) % max; // FIXME: better RNG
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
        return _TRaP_libc___getpid();
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

protected:
    static unsigned int rand_seed;

#if RANDOLIB_LOG_TO_FILE || RANDOLIB_LOG_TO_DEFAULT
    static int log_fd;
#endif
};


// TODO
//#define RANDO_ASSERT(cond) assert(cond)

#define RANDO_ASSERT_STR(x)        #x
#define RANDO_ASSERT_STRM(x)       RANDO_ASSERT_STR(x)
#define RANDO_ASSERT(cond)  ((cond) ? (void)0 \
                                    : (os::API::debug_printf<0>(__FILE__ ":" RANDO_ASSERT_STRM(__LINE__) " assertion failed: " #cond ), __builtin_trap()))

}
#endif // __cplusplus

#endif // __RANDOLIB_OSLINUX_H
