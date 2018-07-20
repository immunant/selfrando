/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <RandoLib.h>
#include <TrapInfo.h>

struct FunctionList;
struct Function;

#ifdef __cplusplus
#include <utility>

#include "util/hashmap.h"

namespace os {

extern "C" {
#include "ModuleInfo.h"
}

class Module : public ModuleBase<Module> {
public:
    typedef ModuleInfo *Handle;
    typedef struct dl_phdr_info *PHdrInfoPointer;

    Module() = delete;
    RANDO_SECTION Module(Handle dynamic_ptr, PHdrInfoPointer phdr_info = nullptr);
    RANDO_SECTION ~Module();

    class Address : public ModuleBase<Module>::AddressBase<Address> {
    public:
        using ModuleBase<Module>::AddressBase<Address>::AddressBase;

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
    };

    class Relocation : public ModuleBase<Module>::RelocationBase<size_t> {
    public:
        Relocation() = delete;

        template<typename Ptr>
        Relocation(const Module &mod, Ptr ptr, Type type)
            : RelocationBase(mod, ptr, type),
              m_has_symbol_ptr(false), m_symbol_ptr(nullptr), m_addend(0) { }

        template<typename Ptr>
        Relocation(const Module &mod, Ptr ptr, Type type, ptrdiff_t addend)
            : RelocationBase(mod, ptr, type),
              m_has_symbol_ptr(false), m_symbol_ptr(nullptr), m_addend(addend) { }

        Relocation(const Module &mod, const trap_reloc_t &reloc)
            : RelocationBase(mod, Address::from_trap(mod, reloc.address).to_ptr(), reloc.type),
              m_symbol_ptr(Address::from_trap(mod, reloc.symbol).to_ptr()), m_addend(reloc.addend) {
            m_has_symbol_ptr = (reloc.symbol != 0); // FIXME: what if zero addresses are legit???
        }

        // TODO: would be nice to move these into RelocationBase
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
        bool m_has_symbol_ptr;
        const BytePointer m_symbol_ptr;
        ptrdiff_t m_addend;
    };

    class Section : public ModuleBase<Module>::SectionBase<Address> {
    public:
        using ModuleBase<Module>::SectionBase<Address>::SectionBase;

        RANDO_SECTION PagePermissions change_permissions(PagePermissions perms) const;

        RANDO_SECTION void flush_icache();
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

public:
    // FIXME: TrapInfo could be pre-computed, and accessed via a function
    typedef void(*ExecSectionCallback)(const Module&, const Section&, ::TrapInfo&, bool, void*);
    RANDO_SECTION void for_all_exec_sections(bool, ExecSectionCallback, void*);

    typedef void(*ModuleCallback)(Module&, void*);
    static RANDO_SECTION void for_all_modules(ModuleCallback, void*);

    RANDO_SECTION void for_all_relocations(FunctionList *functions) const;

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

    RANDO_SECTION void mark_randomized(RandoState);

    // Some loaders add the module base to all entries in .dynamic,
    // e.g., the glibc loaders, while others don't, e.g., the Android one.
    // We set this flag if the addresses have the base.
    bool m_dynamic_has_base;

    Vector<ArchReloc> m_arch_relocs;
    hashmap::HashMap<hashmap::PointerEntry<BytePointer>> m_got_entries;
    size_t m_linker_stubs;

#ifdef RANDOLIB_IS_ARM64
    // Things are tricky on ARM64: we have a bunch of relocations that
    // only give us part of the address of each GOT entry,
    // e.g., R_AARCH64_ADR_GOT_PAGE, so we need to incrementally build
    // the full GOT entry addresses from the components. We keep the
    // partial components in this structure, which is a HashMap entry
    // keyed by the address S of the symbol, and is used to build the
    // corresponding G(GDAT(S+A)) value.
    class ARM64GOTEntry : public hashmap::PointerEntry<BytePointer> {
    private:
        enum Flags {
            FLAG_EMITTED       = 0x01,
            FLAG_HAS_G0        = 0x02,
            FLAG_HAS_G1        = 0x04,
            FLAG_HAS_G2        = 0x08,
            FLAG_HAS_G3        = 0x10,
            FLAG_HAS_PAGE_HI21 = 0x20,
            FLAG_HAS_PAGE_LO12 = 0x40,

            FLAG_HAS_ALL_GROUPS = FLAG_HAS_G0 | FLAG_HAS_G1 |
                                  FLAG_HAS_G2 | FLAG_HAS_G3,
            FLAG_HAS_ALL_PAGE   = FLAG_HAS_PAGE_HI21 | FLAG_HAS_PAGE_LO12,
        };

        uint64_t m_got_group_x = 0;
        int64_t m_got_page_x = 0;
        uint8_t m_flags = 0;

    public:
        ARM64GOTEntry()
            : hashmap::PointerEntry<BytePointer>() { }
        ARM64GOTEntry(BytePointer key)
            : hashmap::PointerEntry<BytePointer>(key) { }

        bool emitted() const {
            return (m_flags & FLAG_EMITTED) != 0;
        }

        void set_emitted() {
            m_flags |= FLAG_EMITTED;
        }

        bool has_all_groups() {
            return (m_flags & FLAG_HAS_ALL_GROUPS) == FLAG_HAS_ALL_GROUPS;
        }

        bool has_all_page() {
            return (m_flags & FLAG_HAS_ALL_PAGE) == FLAG_HAS_ALL_PAGE;
        }

        uint64_t got_group_x() const {
            return m_got_group_x;
        }

        int64_t got_page_x() const {
            return m_got_page_x;
        }

        void set_group(uint64_t grp, size_t idx) {
            RANDO_ASSERT(idx < 4);
            m_got_group_x |= (grp & 0xffff) << (16 * idx);
            m_flags |= (FLAG_HAS_G0 << idx);
        }

        void set_page_hi(int32_t hi) {
            m_got_page_x |= (hi << 12);
            m_flags |= FLAG_HAS_PAGE_HI21;
        }

        void set_page_lo(int32_t lo) {
            m_got_page_x |= (lo & 0xfff);
            m_flags |= FLAG_HAS_PAGE_LO12;
        }
    };
    mutable hashmap::HashMap<ARM64GOTEntry> m_arm64_got_entries;
#endif
};

} // namespace os
#endif // __cplusplus
