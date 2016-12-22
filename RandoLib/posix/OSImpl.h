/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
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

#include <link.h>
#include <utility>
#include <stdio.h>

class TrapInfo;
class TrapReloc;

// Found in posix/qsort.c
extern "C" {
void _TRaP_qsort(void *, size_t, size_t,
                 int (*)(const void *, const void *));
}

namespace os {

// FIXME: gcc doesn't support assigning an entire class to a section
// so we'll either have to solve this using linker scripts
// or include RandoLib as an external shared library
#define RANDO_SECTION

typedef time_t Time;
typedef uint8_t *BytePointer;

// FIXME: move this to a header shared with PatchEntry
enum {
    TRAP_SECTION_TEXT = 0,
    TRAP_SECTION_PLT,
    // Total number of sections
    TRAP_NUM_SECTIONS
};

struct TrapSectionInfoTable {
    uintptr_t start, trap;
    size_t size, trap_size;
};

// ELF-specific information that PatchEntry fills in
struct TrapProgramInfoTable {
    uintptr_t orig_dt_init;
    uintptr_t orig_entry;

    // Location of export trampoline table
    uintptr_t xptramp_start;
    size_t xptramp_size;

    // Location of .text section
    // FIXME: for now, assume that there is only a fixed
    // number of sections and they contain all the code
    // Custom linker scripts may break this
    // We still put in a num_sections field, for future use
    // Also, we use num_sections to mark whether
    // we've added the sections to the table or not
    size_t num_sections;
    TrapSectionInfoTable sections[TRAP_NUM_SECTIONS];
};

class Module {
public:
    struct ModuleInfo {
        BytePointer dynamic;
        TrapProgramInfoTable *program_info_table;
    };
    typedef ModuleInfo *Handle;
    typedef struct dl_phdr_info *PHdrInfoPointer;

    Module() = delete;
    RANDO_SECTION Module(Handle dynamic_ptr, PHdrInfoPointer phdr_info = nullptr);

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
            switch (m_space) {
            case AddressSpace::MEMORY:
                return reinterpret_cast<T>(m_address);
            case AddressSpace::TRAP:
            case AddressSpace::RVA:
                return reinterpret_cast<T>(m_address + reinterpret_cast<uintptr_t>(m_module.m_phdr_info.dlpi_addr));
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

        enum ExtraInfo : uint32_t {
            EXTRA_NONE = 0,
            EXTRA_SYMBOL = 0x1,
            EXTRA_ADDEND = 0x2,
        };

        Relocation() = delete;

        Relocation(const Module &mod, const Address &addr, Type type, bool is_exec = true)
            : m_module(mod), m_orig_src_addr(addr),
              m_src_addr(addr), m_type(type),
              m_has_symbol_addr(false), m_symbol_addr(mod), m_addend(0), m_is_exec(is_exec) { }

        Relocation(const os::Module&, const TrapReloc&, bool is_exec = true);

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
        static Type get_eh_frame_reloc_type();

        static void fixup_export_trampoline(BytePointer*, const Module&, Callback, void*);

        static uint32_t get_extra_info(Type type);

        ptrdiff_t inline get_addend() const {
            return m_addend;
        }

    private:
        const Module &m_module;
        const Address m_orig_src_addr;
        Address m_src_addr;
        Type m_type;
        bool m_is_exec;

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
              m_start(mod, rva, AddressSpace::RVA),
              m_end(mod, rva + size, AddressSpace::RVA),
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

    private:
        const Module &m_module;
        Address m_start, m_end;
        size_t m_size;
    };

    // FIXME: TrapInfo could be pre-computed, and accessed via a function
    typedef void(*ExecSectionCallback)(const Module&, const Section&, ::TrapInfo&, bool, void*);
    RANDO_SECTION void ForAllExecSections(bool, ExecSectionCallback, void*);

    typedef void(*ModuleCallback)(Module&, void*);
    static RANDO_SECTION void ForAllModules(ModuleCallback, void*);

    RANDO_SECTION void ForAllRelocations(Module::Relocation::Callback callback,
                                         void *callback_arg) const;
    RANDO_SECTION void ForAllRelocations(const std::pair<os::BytePointer, os::BytePointer> GOT,
                                         Module::Relocation::Callback callback,
                                         void *callback_arg) const;

    RANDO_SECTION void Fixup_eh_frame_hdr(Module::Relocation::Callback callback,
                                          void *callback_arg) const;

    inline RANDO_SECTION Section export_section() const {
        return Section(*this, m_module_info->program_info_table->xptramp_start,
                              m_module_info->program_info_table->xptramp_size);
    }

    inline RANDO_SECTION BytePointer get_got_ptr() const {
        return m_got;
    }

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

    FILE*m_layout_file = NULL;
    void LFInit(unsigned int seed, BytePointer file_base, void *mem_base, size_t length, const char *name);
public:
    void LFWriteRandomizationRecord(void* undiv_start, void* div_start, uint32_t length) const;
    void LFEnd() const;
};

class APIImpl {
public:
    // Debugging functions and settings
    static const int kDebugLevel = 2;
    static const bool kEnableAsserts = true;

    static void DebugPrintfImpl(const char *fmt, ...);
    static void SystemMessage(const char *fmt, ...);

    template<int level, typename... Args>
    static inline void DebugPrintf(Args... args) {
        // FIXME: this should use std::forward, but can we pull in <utility>???
        if (level <= kDebugLevel)
            DebugPrintfImpl(args...);
    }

    // C library functions
    static inline void QuickSort(void* base, size_t num, size_t size,
                                 int(*cmp)(const void*, const void*)) {
        _TRaP_qsort(base, num, size, cmp);
    }

    static inline void MemCpy(void *dst, const void *src, size_t size) {
        memcpy(dst, src, size);
    }

    static inline int MemCmp(const void *a, const void *b, size_t size) {
        return memcmp(a, b, size);
    }

    static long GetRandom(long max);

    static inline Time GetTime() {
        return time(nullptr); // FIXME: we need something more precise
    }

    static inline unsigned long long TimeDeltaMicroSec(const Time &from, const Time &to) {
        return to - from; // FIXME
    }

protected:
    static unsigned int rand_seed;

public:
    static unsigned inline int getRand_seed() { return rand_seed; }
};


// TODO
#define RANDO_ASSERT(cond) assert(cond)

}

#endif // __RANDOLIB_OSLINUX_H
