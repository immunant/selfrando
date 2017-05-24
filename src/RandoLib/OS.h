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
struct RANDO_SECTION FunctionList;
class TrapInfo;

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
                                               const Address &end) const;
        inline RANDO_SECTION bool operator==(const Address &other) const;
        inline RANDO_SECTION bool operator<(const Address &other) const;

        static inline RANDO_SECTION
        Address from_trap(const Module &mod, uintptr_t addr) {
            return Address(mod, addr, AddressSpace::TRAP);
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
#else
#error "Unrecognized OS"
#endif

namespace os {

// Implement some of the inline functions that depend on os::Module
template<>
template<>
inline RANDO_SECTION
bool ModuleBase<Module>::AddressBase<Module::Address>::inside_range(
        const Module::Address &start, const Module::Address &end) const {
    auto  this_addr = os_address().to_ptr<uintptr_t>();
    auto start_addr = start.to_ptr<uintptr_t>();
    auto   end_addr = end.to_ptr<uintptr_t>();
    return (this_addr >= start_addr) && (this_addr < end_addr);
}

template<>
template<>
inline RANDO_SECTION
bool ModuleBase<Module>::AddressBase<Module::Address>::operator==(
        const Module::Address &other) const {
    return os_address().to_ptr<uintptr_t>() == other.to_ptr<uintptr_t>();
}

template<>
template<>
inline RANDO_SECTION
bool ModuleBase<Module>::AddressBase<Module::Address>::operator<(
        const Module::Address &other) const {
    return os_address().to_ptr<uintptr_t>() < other.to_ptr<uintptr_t>();
}

} // namespace os

#endif  // __cplusplus

#endif // __RANDOLIB_OS_H
