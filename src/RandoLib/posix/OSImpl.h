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
#include <utility>

class TrapInfo;
struct trap_reloc_t;

struct FunctionList;
struct Function;

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

extern "C" {
#include "ModuleInfo.h"
}

typedef time_t Time;
typedef int File;
typedef pid_t Pid;

static const File kInvalidFile = -1;

class Module {
public:
    typedef ModuleInfo *Handle;
    typedef struct dl_phdr_info *PHdrInfoPointer;

    Module() = delete;
    RANDO_SECTION Module(Handle dynamic_ptr, PHdrInfoPointer phdr_info = nullptr);
    RANDO_SECTION ~Module();

    class Address {
    public:
        // No default construction (addresses should always have a module)
        Address() = delete;

        Address(const Module &mod, uintptr_t addr = 0,
                AddressSpace space = AddressSpace::MEMORY)
            : m_address(addr), m_space(space), m_module(mod) {}

        RANDO_SECTION void Reset(const Module &mod, uintptr_t addr = 0,
                                 AddressSpace space = AddressSpace::MEMORY);

        template<typename T = BytePointer>
        inline RANDO_SECTION T to_ptr() const {
		//assert((sizeof(uintptr_t)==1));
            switch (m_space) {
            case AddressSpace::MEMORY:
            case AddressSpace::TRAP:
                return reinterpret_cast<T>(m_address);
            case AddressSpace::RVA:
                //return reinterpret_cast<T>(m_address + reinterpret_cast<uintptr_t>(m_module.m_phdr_info.dlpi_addr));
                return reinterpret_cast<T>(m_address + static_cast<uintptr_t>(m_module.m_phdr_info.dlpi_addr));
            default:
                return 0;
            }
        }

        inline RANDO_SECTION bool inside_range(const Address &start, const Address &end) const {
            auto  this_addr = to_ptr<uintptr_t>();
            auto start_addr = start.to_ptr<uintptr_t>();
            auto   end_addr = end.to_ptr<uintptr_t>();
            return (this_addr >= start_addr) && (this_addr < end_addr);
        }

        inline RANDO_SECTION bool operator==(const Address &other) const {
            return to_ptr<uintptr_t>() == other.to_ptr<uintptr_t>();
        }

        inline RANDO_SECTION bool operator<(const Address &other) const {
            return to_ptr<uintptr_t>() < other.to_ptr<uintptr_t>();
        }

    private:
        uintptr_t m_address;
        AddressSpace m_space;
        const Module &m_module;
    };

    class Relocation {
    public:
        typedef size_t Type;
        typedef void(*Callback)(Relocation&, void*);

        Relocation() = delete;

        Relocation(const Module &mod, const Address &addr, Type type)
            : m_module(mod), m_orig_src_addr(addr),
              m_src_addr(addr), m_type(type),
              m_has_symbol_addr(false), m_symbol_addr(mod), m_addend(0) { }

        Relocation(const Module &mod, const Address &addr, Type type, ptrdiff_t addend)
            : m_module(mod), m_orig_src_addr(addr),
              m_src_addr(addr), m_type(type),
              m_has_symbol_addr(false), m_symbol_addr(mod), m_addend(addend) { }

        Relocation(const os::Module&, const trap_reloc_t&);

        Type get_type() const {
            return m_type;
        }

        Address get_original_source_address() const {
            return m_orig_src_addr;
        }

        Address get_source_address() const {
            return m_src_addr;
        }

        BytePointer get_source_ptr() const {
            return m_src_addr.to_ptr();
        }

        void set_source_ptr(BytePointer new_source) {
            m_src_addr.Reset(m_module, reinterpret_cast<uintptr_t>(new_source));
        }

        BytePointer get_target_ptr() const;
        void set_target_ptr(BytePointer);

        static Type get_pointer_reloc_type();

        static void fixup_export_trampoline(BytePointer*, const Module&, Callback, void*);
        static void fixup_entry_point(const Module&, uintptr_t, uintptr_t);

        inline ptrdiff_t get_addend() const {
            return m_addend;
        }

        bool already_applied() const {
            auto *arch_reloc = m_module.find_arch_reloc(m_orig_src_addr);
            return arch_reloc != nullptr && arch_reloc->applied;
        }

        void mark_applied() {
            auto *arch_reloc = m_module.find_arch_reloc(m_orig_src_addr);
            if (arch_reloc != nullptr)
                arch_reloc->applied = true;
        }

    private:
        const Module &m_module;
        const Address m_orig_src_addr;
        Address m_src_addr;
        Type m_type;

        bool m_has_symbol_addr;
        const Address m_symbol_addr;
        ptrdiff_t m_addend;
    };

    // Get an Address for a RVA; no outside functions should call this
    // FIXME: make this a private function, after removing all outside refs
    inline RANDO_SECTION Address address_from_ptr(uintptr_t addr) const {
        return Address(*this, addr, AddressSpace::MEMORY);
    }

    template<typename T>
    inline RANDO_SECTION Address address_from_ptr(T* ptr) const {
        return Address(*this, reinterpret_cast<uintptr_t>(ptr), AddressSpace::MEMORY);
    }

    inline RANDO_SECTION Address address_from_trap(uintptr_t addr) const {
        return Address(*this, addr, AddressSpace::TRAP);
    }

    class Section {
    public:
        // No default construction (sections should always have a module)
        Section() = delete;

        Section(const Module &mod, uintptr_t rva = 0, size_t size = 0)
            : m_module(mod),
              m_start(mod, rva, AddressSpace::MEMORY),
              m_end(mod, rva + size, AddressSpace::MEMORY),
              m_size(size) {}

        template<typename T>
        inline RANDO_SECTION bool contains_addr(const T* ptr) const {
            Address addr(m_module, reinterpret_cast<uintptr_t>(ptr), os::AddressSpace::MEMORY);
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

        RANDO_SECTION PagePermissions MemProtect(PagePermissions perms) const;

        // This flushes the icache/dcache for this section.
        RANDO_SECTION void flush_icache();

    private:
        const Module &m_module;
        Address m_start, m_end;
        size_t m_size;
    };

    struct ArchReloc {
        // Cannot use Address here because we run into trouble with
        // Address's copy-assignment and move-assignment operators
        os::BytePointer address;
        Relocation::Type type;
        bool applied;
    };

    // FIXME: TrapInfo could be pre-computed, and accessed via a function
    typedef void(*ExecSectionCallback)(const Module&, const Section&, ::TrapInfo&, bool, void*);
    RANDO_SECTION void ForAllExecSections(bool, ExecSectionCallback, void*);

    typedef void(*ModuleCallback)(Module&, void*);
    static RANDO_SECTION void ForAllModules(ModuleCallback, void*);

    RANDO_SECTION void ForAllRelocations(FunctionList *functions,
                                         Module::Relocation::Callback callback,
                                         void *callback_arg) const;

    RANDO_SECTION void preprocess_arch();
    RANDO_SECTION void relocate_arch(FunctionList *functions,
                                     Module::Relocation::Callback callback,
                                     void *callback_arg) const;

    inline RANDO_SECTION Section export_section() const {
        return Section(*this, m_module_info->program_info_table->xptramp_start,
                              m_module_info->program_info_table->xptramp_size);
    }

    inline RANDO_SECTION BytePointer get_got_ptr() const {
        return m_got;
    }

    inline RANDO_SECTION const char *get_module_name() const {
        return m_phdr_info.dlpi_name;
    }

    RANDO_SECTION ArchReloc *find_arch_reloc(const Address &address) const;

#if RANDOLIB_WRITE_LAYOUTS
    void write_layout_file(FunctionList *functions,
                           size_t *shuffled_order) const;
#endif

private:
    ModuleInfo *m_module_info;
    BytePointer m_image_base;
    BytePointer m_got;
    BytePointer m_eh_frame_hdr;

    // We keep our own copy of dl_phdr_info structure
    // since dl_iterate_phdr seems to reuse its own
    struct dl_phdr_info m_phdr_info;

    inline RANDO_SECTION Address RVA2Address(uintptr_t rva) const {
        return Address(*this, rva, AddressSpace::RVA);
    }

    enum RandoState : uint32_t {
        NOT_RANDOMIZED = 0, // This must be 0, to match the default
        RANDOMIZED = 1,
        CANT_RANDOMIZE = 2,
        SELF_RANDOMIZE = 3,
    };

    RANDO_SECTION void MarkRandomized(RandoState);

    // Some loaders add the module base to all entries in .dynamic,
    // e.g., the glibc loaders, while others don't, e.g., the Android one.
    // We set this flag if the addresses have the base.
    bool m_dynamic_has_base;

    ArchReloc *m_arch_relocs;
    size_t m_num_arch_relocs;
    size_t m_linker_stubs;
};

class APIImpl {
public:
    static void DebugPrintfImpl(const char *fmt, ...);
    static void SystemMessage(const char *fmt, ...);

    // C library functions
    static inline void QuickSort(void* base, size_t num, size_t size,
                                 int(*cmp)(const void*, const void*)) {
        _TRaP_qsort(base, num, size, cmp);
    }

    static inline void MemCpy(void *dst, const void *src, size_t size) {
        _TRaP_libc_memcpy(dst, src, size);
    }

    static inline int MemCmp(const void *a, const void *b, size_t size) {
        return _TRaP_libc_memcmp(a, b, size);
    }

    static inline size_t GetRandom(size_t max) {
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

    static inline Time GetTime() {
        return _TRaP_libc_time(nullptr); // FIXME: we need something more precise
    }

    static inline unsigned long long TimeDeltaMicroSec(const Time &from, const Time &to) {
        return to - from; // FIXME
    }

    static char *GetEnv(const char *var) {
        return _TRaP_libc_getenv(var);
    }

    static Pid GetPid() {
        return _TRaP_libc___getpid();
    }

    // TODO: make this into a compile-time value,
    // or maybe a run-time one, and also a TRaP
    // info setting
    static const int kFunctionAlignment = 4;
    static const int kTextAlignment = 4096;
    static const int kPageAlignment = 4096;
    static const bool kPreserveFunctionOffset = true;

    static bool Is1ByteNOP(BytePointer);
    static void InsertNOPs(BytePointer, size_t);

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
                                    : (os::API::DebugPrintf<0>(__FILE__ ":" RANDO_ASSERT_STRM(__LINE__) " assertion failed: " #cond ), __builtin_trap()))

}
#endif // __cplusplus

#endif // __RANDOLIB_OSLINUX_H
