/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the University of California nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <Windows.h>
#include <winternl.h>

#ifdef __cplusplus

namespace os {

// For some reason, MSVC doesn't have ssize_t
typedef SSIZE_T ssize_t;

// OS-specific typedefs
typedef LARGE_INTEGER Time;
typedef BYTE *BytePointer;
typedef HANDLE File;
typedef DWORD Pid;

const File kInvalidFile = INVALID_HANDLE_VALUE;

template<typename T>
class RANDO_SECTION __declspec(novtable) Buffer final {
public:
    Buffer() : m_ptr(nullptr), m_capacity(0) {}

    Buffer(size_t capacity) : m_ptr(nullptr), m_capacity(0) {
        ensure(capacity);
    }

    ~Buffer() {
        clear();
    }

    void ensure(size_t);

    T *data() {
        return m_ptr;
    }

    size_t capacity() {
        return m_capacity;
    }

    void clear();

    static Buffer<T> *new_buffer();

    static void release_buffer(Buffer<T>*);

private:
    T *m_ptr;
    size_t m_capacity;
};

class RANDO_SECTION APIImpl : public APIBase<APIImpl> {
public:
    static void SystemMessage(const char *fmt, ...);

    // C library functions
    static inline void memcpy(void *dst, const void *src, size_t size) {
        RANDO_SYS_FUNCTION(ntdll, memcpy, dst, src, size);
    }

    static inline int memcmp(const void *a, const void *b, size_t size) {
        return RANDO_SYS_FUNCTION(ntdll, memcmp, a, b, size);
    }

    static inline void *memset(void *s, int c, size_t n) {
        return RANDO_SYS_FUNCTION(ntdll, memset, s, c, n);
    }

    using APIBase::clz;
    using APIBase::random;
    using APIBase::random_full;

    static inline Time time() {
        LARGE_INTEGER res;
        RANDO_SYS_FUNCTION(kernel32, QueryPerformanceCounter, &res);
        return res;
    }

    static inline LONGLONG usec_between(const Time &from, const Time &to) {
        LONGLONG res = to.QuadPart - from.QuadPart;
#if RANDOLIB_IS_X86
        res = RANDO_SYS_FUNCTION(ntdll, allmul, res, 1000000);
        res = RANDO_SYS_FUNCTION(ntdll, alldiv, res, timer_freq.QuadPart);
#else
        res *= 1000000LL;
        res /= timer_freq.QuadPart;
#endif
        return res;
    }

    static char *getenv(const char *var);

    static Pid getpid();

    // TODO: make this into a compile-time value,
    // or maybe a run-time one, and also a TRaP
    // info setting
    static const int kFunctionP2Align = 0;
    static const int kTextAlignment = 1;
    static const int kPageAlignment = 4096;
    static const bool kPreserveFunctionOffset = true;

    static bool is_one_byte_nop(BytePointer);
    static void insert_nops(BytePointer, size_t);

protected:
    static void debug_printf_impl(const char *fmt, ...);

protected:
    // Other Windows globals
    static HMODULE ntdll, kernel32;
    static LARGE_INTEGER timer_freq;
    static uint32_t rand_seed[RANDOLIB_SEED_WORDS];

    static Buffer<char> *env_buf;

#define SYS_FUNCTION(library, name, API, result_type, ...)   static result_type (API *library##_##name)(__VA_ARGS__);
#include "SysFunctions.inc"
#undef SYS_FUNCTION
    friend class Module;
};

template<>
template<>
inline int APIBase<APIImpl>::clz(uint32_t x) {
    DWORD clz = 0;
    _BitScanReverse(&clz, x);
    return 31 - clz;
}

#if RANDOLIB_IS_X86_64
template<>
template<>
inline int APIBase<APIImpl>::clz(uint64_t x) {
    DWORD clz = 0;
    _BitScanReverse64(&clz, x);
    return 63 - clz;
}
#endif // RANDOLIB_IS_X86_64

template<>
template<>
inline uint32_t APIBase<APIImpl>::random_full() {
#if RANDOLIB_RNG_IS_CHACHA
    extern RANDO_SECTION uint32_t _TRaP_chacha_random_u32();
    return _TRaP_chacha_random_u32();
#else // RANDOLIB_RNG_IS_CHACHA
    // TODO: do we need the seed???
    return RANDO_SYS_FUNCTION(ntdll, RtlRandomEx,
                              reinterpret_cast<PULONG>(&rand_seed[0]));
#endif // RANDOLIB_RNG_IS_CHACHA
}

}
#endif // __cplusplus
