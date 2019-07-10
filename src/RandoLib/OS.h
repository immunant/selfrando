/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#ifndef __RANDOLIB_OS_H
#define __RANDOLIB_OS_H
#pragma once

#if RANDOLIB_IS_WIN32
#include "win32/OSDefs.h"
#elif RANDOLIB_IS_POSIX
#include "posix/OSDefs.h"
#elif RANDOLIB_IS_BAREFLANK
#include "bareflank/OSDefs.h"
#else
#error "Unrecognized OS"
#endif

#ifndef RANDOLIB_SEED_WORDS
#if RANDOLIB_RNG_IS_CHACHA
#define RANDOLIB_SEED_WORDS 8
#else // RANDOLIB_RNG_IS_CHACHA
#define RANDOLIB_SEED_WORDS 1
#endif // RANDOLIB_RNG_IS_CHACHA
#endif // RANDOLIB_SEED_WORDS

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

extern "C" {
void _TRaP_qsort(void *, size_t, size_t,
                 int(*)(const void *, const void *));
}

// Base class for APIImpl subclasses to inherit from
template<typename Impl>
class RANDO_SECTION APIBase {
public:
    // C library functions
    static inline void qsort(void* base, size_t num, size_t size,
                             int(*cmp)(const void*, const void*)) {
        _TRaP_qsort(base, num, size, cmp);
    }

    // Our own implementation of std::swap() that does basically the same
    // thing, without relying on C++ headers
    template<typename T>
    static inline void swap(T &a, T &b) {
        // We can't use std::move(), so we manually do what it does internally
        // FIXME: if our compiler is too old and doesn't do rvalue-references,
        // fall back to regular assigment
        T tmp = static_cast<T&&>(a);
        a = static_cast<T&&>(b);
        b = static_cast<T&&>(tmp);
    }

    // Count Leading Zeroes: returns the number of zeroes that the
    // binary representation of `x` starts with
    template<typename T>
    static inline int clz(T x);

    // Return a uniformly-distributed number in the range [0, max)
    template<typename T>
    static inline T random(T max) {
        if (max == 0)
            return 0;

        auto clz = Impl::template clz<T>(max);
        auto mask = static_cast<T>(-1LL) >> clz;
        for (;;) {
            // Clip rand to next power of 2 after "max"
            // This ensures that we always have
            // P(rand < max) > 0.5
            auto rand = Impl::template random_full<T>() & mask;
            if (rand < max)
                return rand;
        }
    }

    // Return a random number from the entire set of values of type `T`,
    // e.g., 0..2^32-1 if T==uint32_t
    template<typename T>
    static inline T random_full() {
        // The default implementation forwards everything to
        // random_full<uint32_t>()
        constexpr size_t wsize = sizeof(uint32_t);
        constexpr size_t words = (sizeof(T) + wsize - 1) / wsize;
        union {
            uint32_t x32[words];
            T xt;
        } x;
        for (size_t i = 0; i < words; i++)
            x.x32[i] = Impl::template random_full<uint32_t>();
        return x.xt;
    }
};

}
#endif // __cplusplus

#if RANDOLIB_IS_WIN32
#include "win32/OSImpl.h"
#elif RANDOLIB_IS_POSIX
#include "posix/OSImpl.h"
#elif RANDOLIB_IS_BAREFLANK
#include "bareflank/OSImpl.h"
#else
#error "Unrecognized OS"
#endif

#ifdef __cplusplus
struct RANDO_SECTION FunctionList;
class TrapInfo;

namespace os {

class RANDO_SECTION API : public APIImpl {
public:
    static void init();
    static void finish();

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
    static inline void debug_printf(Args... args) {
        // FIXME: this should use std::forward, but can we pull in <utility>???
        if (level <= debug_level)
            debug_printf_impl(args...);
    }

    template<typename To, typename From>
    static inline RANDO_SECTION To assert_cast(From x) {
        RANDO_ASSERT(static_cast<From>(static_cast<To>(x)) == x &&
                     "Value for cast does not fit in target type");
        return static_cast<To>(x);
    }

    // Explicitly list functions inherited from APIImpl, so compilation fails if they're missing
    using APIImpl::qsort;
    using APIImpl::memcpy;
    using APIImpl::memcmp;
    using APIImpl::memset;
    using APIImpl::clz;
    using APIImpl::random;
    using APIImpl::random_full;
    using APIImpl::time;
    using APIImpl::getenv;
    using APIImpl::getpid;
    using APIImpl::usec_between;
    using APIImpl::debug_printf_impl;

    // Architecture-specific functions/constants
    using APIImpl::is_one_byte_nop;
    using APIImpl::insert_nops;

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

    static void *mem_alloc(size_t, bool zeroed = false);
    static void *mem_realloc(void*, size_t, bool zeroed = false);
    static void mem_free(void*);

    static void *mmap(void*, size_t, PagePermissions, bool); // TODO
    static void munmap(void*, size_t, bool); // TODO
    static PagePermissions mprotect(void*, size_t, PagePermissions);

    static File open_file(const char *name, bool write, bool create);
    static ssize_t read_file(File file, void *buf, size_t len);
    static ssize_t write_file(File file, const void *buf, size_t len);
    static void close_file(File file);

#if RANDOLIB_WRITE_LAYOUTS > 0
    static File open_layout_file(bool write);
#endif
};

// Use the CRTP pattern to implement the OS-independent parts as superclasses
template<typename Module>
class RANDO_SECTION ModuleBase {
protected:
    // Only subclasses can instantiate this
    ModuleBase() = default;
    ~ModuleBase() = default;

    template<typename Address>
    class RANDO_SECTION AddressBase {
    public:
        // No default construction (addresses should always have a module)
        AddressBase() = delete;

        AddressBase(const Module &mod, uintptr_t addr = 0,
                    AddressSpace space = AddressSpace::MEMORY)
            : m_address(addr), m_space(space), m_module(mod) {}

        inline RANDO_SECTION void reset(const Module &mod, uintptr_t addr = 0,
                                        AddressSpace space = AddressSpace::MEMORY) {
            RANDO_ASSERT(&mod == &m_module); // We can only reset addresses to the same module
            m_address = addr;
            m_space = space;
        }

        inline RANDO_SECTION bool inside_range(const Address &start,
                                               const Address &end) const {
            auto  this_addr = os_address().template to_ptr<uintptr_t>();
            auto start_addr = start.template to_ptr<uintptr_t>();
            auto   end_addr = end.template to_ptr<uintptr_t>();
            return (this_addr >= start_addr) && (this_addr < end_addr);
        }

        inline RANDO_SECTION bool operator==(const Address &other) const {
            return os_address().template to_ptr<uintptr_t>() ==
                          other.template to_ptr<uintptr_t>();
        }

        inline RANDO_SECTION bool operator<(const Address &other) const {
            return os_address().template to_ptr<uintptr_t>() <
                          other.template to_ptr<uintptr_t>();
        }

        // FIXME: we should use trap_address_t here, but it's not available
        template<typename TrapAddress>
        static inline RANDO_SECTION
        Address from_trap(const Module &mod, TrapAddress addr) {
            return Address(mod, API::assert_cast<uintptr_t>(addr), AddressSpace::TRAP);
        }

    protected:
        uintptr_t m_address;
        AddressSpace m_space;
        const Module &m_module;

    private:
        const Address &os_address() const {
            return *static_cast<const Address*>(this);
        }
    };

    template<typename RelocType>
    class RANDO_SECTION RelocationBase {
    public:
        typedef RelocType Type;

        RelocationBase() = delete;

        Type get_type() const {
            return m_type;
        }

        BytePointer get_original_source_ptr() const {
            return m_orig_src_ptr;
        }

        BytePointer get_source_ptr() const {
            return m_src_ptr;
        }

        void set_source_ptr(BytePointer new_source) {
            m_src_ptr = new_source;
        }

    protected:
        template<typename Ptr>
        RelocationBase(const Module &mod, Ptr ptr, Type type)
            : m_module(mod), m_orig_src_ptr(reinterpret_cast<BytePointer>(ptr)),
              m_src_ptr(reinterpret_cast<BytePointer>(ptr)), m_type(type) { }

        // Helper functions for the arch-specific code
        template<typename T>
        void set_i32(T x) {
            *reinterpret_cast<int32_t*>(m_src_ptr) = API::assert_cast<int32_t>(x);
        }

        template<typename T>
        void set_i64(T x) {
            *reinterpret_cast<int64_t*>(m_src_ptr) = API::assert_cast<int64_t>(x);
        }

        template<typename T>
        void set_u32(T x) {
            *reinterpret_cast<uint32_t*>(m_src_ptr) = API::assert_cast<uint32_t>(x);
        }

        template<typename T>
        void set_u64(T x) {
            *reinterpret_cast<uint64_t*>(m_src_ptr) = API::assert_cast<uint64_t>(x);
        }

        template<typename T>
        void set_p32(T *x) {
            set_u32(reinterpret_cast<uintptr_t>(x));
        }

        template<typename T>
        void set_p64(T *x) {
            set_u64(reinterpret_cast<uintptr_t>(x));
        }

    protected:
        const Module &m_module;
        const BytePointer m_orig_src_ptr;
        BytePointer m_src_ptr;
        Type m_type;
    };

    template<typename Address>
    class RANDO_SECTION SectionBase {
    public:
        // No default construction (sections should always have a module)
        SectionBase() = delete;

        SectionBase(const Module &mod, uintptr_t rva = 0, size_t size = 0,
                    AddressSpace space = AddressSpace::MEMORY)
            : m_module(mod), 
              m_start(mod, rva, space),
              m_end(mod, rva + size, space),
              m_size(size) { }

        template<typename T>
        inline RANDO_SECTION bool contains_addr(const T* ptr) const {
            Address addr(m_module,
                         reinterpret_cast<uintptr_t>(ptr),
                         os::AddressSpace::MEMORY);
            return contains_addr(addr);
        }

        inline RANDO_SECTION bool contains_addr(const Address &addr) const {
            return addr.inside_range(m_start, m_end);
        }

        inline RANDO_SECTION Address start() const {
            return m_start;
        }

        inline RANDO_SECTION Address end() const {
            return m_end;
        }

        inline RANDO_SECTION size_t size() const {
            return m_size;
        }

        inline RANDO_SECTION bool empty() const {
            return m_size == 0;
        }

    protected:
        const Module &m_module;
        Address m_start, m_end;
        size_t m_size;
    };

public:

private:
    const Module &os_module() const {
        return *static_cast<const Module*>(this);
    }
};

} // namespace os

#if RANDOLIB_IS_WIN32
#include "win32/OSModule.h"
#elif RANDOLIB_IS_POSIX
#include "posix/OSModule.h"
#elif RANDOLIB_IS_BAREFLANK
#include "bareflank/OSModule.h"
#else
#error "Unrecognized OS"
#endif

#endif  // __cplusplus

#endif // __RANDOLIB_OS_H
