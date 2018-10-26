/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2018 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <RandoLib.h>
#include <TrapInfo.h>

#include <bfelf_loader.h>

struct FunctionList;
struct Function;

#ifdef __cplusplus

// We can't #include <new> on bareflank due to compiler errors (FIXME),
// so we just reimplement placement new ourselves
inline void *operator new(size_t s, void *p) throw() {
    return p;
}

#include "util/hashmap.h"

namespace os {

class Module : public ModuleBase<Module> {
public:
    typedef struct bfelf_file_t *Handle;

    Module() = delete;
    RANDO_SECTION Module(Handle bfelf_file);
    RANDO_SECTION ~Module();

    class Address : public ModuleBase<Module>::AddressBase<Address> {
    public:
        using ModuleBase<Module>::AddressBase<Address>::AddressBase;

        template<typename T = BytePointer>
        inline RANDO_SECTION T to_ptr() const {
            switch (m_space) {
            case AddressSpace::MEMORY:
            case AddressSpace::TRAP:
                return reinterpret_cast<T>(m_address);
            case AddressSpace::RVA:
                return reinterpret_cast<T>(m_address + m_module.m_bfelf_file->exec_addr -
                                           m_module.m_bfelf_file->start_addr);
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

        // Unlike the posix version, this can't be inlined here
        // because that causes a linking error due to `-mfentry`
        Relocation(const Module &mod, const trap_reloc_t &reloc);

        // TODO: would be nice to move these into RelocationBase
        BytePointer get_target_ptr() const;
        void set_target_ptr(BytePointer);

        static Type get_pointer_reloc_type();

        static void fixup_export_trampoline(BytePointer*, const Module&, FunctionList*);
        static void fixup_entry_point(const Module&, uintptr_t, uintptr_t);

        inline ptrdiff_t get_addend() const {
            return m_addend;
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

public:
    // FIXME: TrapInfo could be pre-computed, and accessed via a function
    typedef void(*ExecSectionCallback)(const Module&, const Section&, ::TrapInfo&, bool, void*);
    RANDO_SECTION void for_all_exec_sections(bool, ExecSectionCallback, void*);

    typedef void(*ModuleCallback)(Module&, void*);
    static RANDO_SECTION void for_all_modules(ModuleCallback, void*);

    RANDO_SECTION void for_all_relocations(FunctionList *functions) const;

    RANDO_SECTION void preprocess_arch();
    RANDO_SECTION void relocate_arch(FunctionList *functions) const;

    inline RANDO_SECTION Section export_section() const {
        return Section(*this);
    }

    inline RANDO_SECTION BytePointer get_got_ptr() const {
        return RVA2Address(m_bfelf_file->pltgot).to_ptr();
    }

    inline RANDO_SECTION const char *get_module_name() const {
        return "bareflank"; // FIXME
    }

#if RANDOLIB_WRITE_LAYOUTS
    void write_layout_file(FunctionList *functions,
                           size_t *shuffled_order) const;
#endif

    RANDO_SECTION void read_got_relocations(const TrapInfo *trap_info);

private:
    struct bfelf_file_t *m_bfelf_file;

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

    hashmap::HashMap<hashmap::PointerEntry<BytePointer>> m_got_entries;
    size_t m_linker_stubs;
};

} // namespace os
#endif // __cplusplus
