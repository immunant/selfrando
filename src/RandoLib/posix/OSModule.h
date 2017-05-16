/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <RandoLib.h>

class TrapInfo;
struct trap_reloc_t;

struct FunctionList;
struct Function;

#ifdef __cplusplus
#include <utility>

namespace os {

extern "C" {
#include "ModuleInfo.h"
}

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

        Relocation() = delete;

        Relocation(const Module &mod, const Address &addr, Type type)
            : m_module(mod), m_orig_src_ptr(addr.to_ptr()),
              m_src_ptr(addr.to_ptr()), m_type(type),
              m_has_symbol_ptr(false), m_symbol_ptr(nullptr), m_addend(0) { }

        Relocation(const Module &mod, const Address &addr, Type type, ptrdiff_t addend)
            : m_module(mod), m_orig_src_ptr(addr.to_ptr()),
              m_src_ptr(addr.to_ptr()), m_type(type),
              m_has_symbol_ptr(false), m_symbol_ptr(nullptr), m_addend(addend) { }

        Relocation(const os::Module&, const trap_reloc_t&);

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

        BytePointer get_target_ptr() const;
        void set_target_ptr(BytePointer);

        static Type get_pointer_reloc_type();

        static void fixup_export_trampoline(BytePointer*, const Module&, FunctionList*);
        static void fixup_entry_point(const Module&, uintptr_t, uintptr_t);

        inline ptrdiff_t get_addend() const {
            return m_addend;
        }

        bool already_applied() const {
            auto *arch_reloc = m_module.find_arch_reloc(m_orig_src_ptr);
            return arch_reloc != nullptr && arch_reloc->applied;
        }

        void mark_applied() {
            auto *arch_reloc = m_module.find_arch_reloc(m_orig_src_ptr);
            if (arch_reloc != nullptr)
                arch_reloc->applied = true;
        }

        BytePointer get_got_entry() const;

    private:
        const Module &m_module;
        const BytePointer m_orig_src_ptr;
        BytePointer m_src_ptr;
        Type m_type;

        bool m_has_symbol_ptr;
        const BytePointer m_symbol_ptr;
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

        static int sort_compare(const void *pa, const void *pb) {
            auto ra = reinterpret_cast<const os::Module::ArchReloc*>(pa);
            auto rb = reinterpret_cast<const os::Module::ArchReloc*>(pb);
            return  (ra->address <  rb->address) ? -1 :
                   ((ra->address == rb->address) ?  0 : 1);
        }
    };

    // FIXME: TrapInfo could be pre-computed, and accessed via a function
    typedef void(*ExecSectionCallback)(const Module&, const Section&, ::TrapInfo&, bool, void*);
    RANDO_SECTION void ForAllExecSections(bool, ExecSectionCallback, void*);

    typedef void(*ModuleCallback)(Module&, void*);
    static RANDO_SECTION void ForAllModules(ModuleCallback, void*);

    RANDO_SECTION void ForAllRelocations(FunctionList *functions) const;

    template<typename RelType>
    RANDO_SECTION Relocation::Type arch_reloc_type(const RelType *dyn_reloc);

    template<typename DynType, typename RelType,
             size_t dt_relocs, size_t dt_relocs_size>
    RANDO_SECTION void build_arch_relocs();

    RANDO_SECTION void preprocess_arch();
    RANDO_SECTION void relocate_arch(FunctionList *functions) const;

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

    RANDO_SECTION ArchReloc *find_arch_reloc(BytePointer address_ptr) const;

#if RANDOLIB_WRITE_LAYOUTS
    void write_layout_file(FunctionList *functions,
                           size_t *shuffled_order) const;
#endif

    RANDO_SECTION void read_got_relocations(const TrapInfo *trap_info);

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

    Vector<ArchReloc> m_arch_relocs;
    Vector<BytePointer> m_got_entries;
    size_t m_linker_stubs;
};

} // namespace os
#endif // __cplusplus
