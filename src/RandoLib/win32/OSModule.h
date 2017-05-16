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

#include <RandoLib.h>
#include <TrapInfo.h>

struct FunctionList;
struct Function;

#ifdef __cplusplus

namespace os {

class RANDO_SECTION Module {
public:
    struct ModuleInfo {
        uintptr_t original_entry_rva;
        BytePointer entry_loop;
        DWORD file_header_characteristics;
        HANDLE module;
    };
    typedef ModuleInfo *Handle;

    Module() = delete;
    Module(Handle info, UNICODE_STRING *name = nullptr);
    ~Module();

    class RANDO_SECTION Address {
    public:
        // No default construction (addresses should always have a module)
        Address() = delete;

        Address(const Module &mod, uintptr_t addr = 0,
                AddressSpace space = AddressSpace::MEMORY)
            : m_address(addr), m_space(space), m_module(mod) {
        }

        RANDO_SECTION void Reset(const Module &mod, uintptr_t addr = 0,
                                 AddressSpace space = AddressSpace::MEMORY);

        template<typename T = BytePointer>
        inline RANDO_SECTION T to_ptr() const {
            switch (m_space) {
            case AddressSpace::MEMORY:
                return reinterpret_cast<T>(m_address);
            case AddressSpace::TRAP:
            case AddressSpace::RVA:
                return reinterpret_cast<T>(m_address + reinterpret_cast<uintptr_t>(m_module.m_handle));
            default:
                return 0;
            }
        }

        template<>
        inline RANDO_SECTION uintptr_t to_ptr() const {
            switch (m_space) {
            case AddressSpace::MEMORY:
                return m_address;
            case AddressSpace::TRAP:
            case AddressSpace::RVA:
                return m_address + reinterpret_cast<uintptr_t>(m_module.m_handle);
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
        typedef DWORD Type;

        Relocation() = delete;

        template<typename Ptr>
        Relocation(const Module &mod, Ptr ptr, Type type)
            : m_module(&mod), m_orig_src_ptr(reinterpret_cast<BytePointer>(ptr)),
              m_src_ptr(reinterpret_cast<BytePointer>(ptr)), m_type(type) {
        }

        Relocation(const os::Module &mod, const trap_reloc_t &reloc)
            : m_module(&mod), m_orig_src_ptr(mod.address_from_trap(reloc.address).to_ptr()),
              m_src_ptr(mod.address_from_trap(reloc.address).to_ptr()), m_type(reloc.type) {
        }

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

        static Type type_from_based(Type based_type);

        static void fixup_export_trampoline(BytePointer*, const Module&, FunctionList*);

        bool already_applied() const {
            return false;
        }

        void mark_applied() {}

    private:
        const Module *m_module;
        BytePointer m_orig_src_ptr;
        BytePointer m_src_ptr;
        Type m_type;
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

    template<typename T>
    inline RANDO_SECTION void relocate_rva(T *rva,
                                           FunctionList *functions,
                                           bool subtract_one) const {
        auto full_addr = reinterpret_cast<uintptr_t>(m_handle) + *rva;
        // If we're relocating an RVA that points to one byte past the end
        // of something (like a function), subtract one byte so we land inside
        // the object we're relocating
        if (subtract_one)
            full_addr--;
        Relocation rva_reloc(*this, &full_addr, Relocation::get_pointer_reloc_type());
        add_relocation(rva_reloc);
        if (subtract_one)
            full_addr++;

        auto new_rva = full_addr - reinterpret_cast<uintptr_t>(m_handle);
        RANDO_ASSERT(static_cast<T>(new_rva) == new_rva);
        *rva = static_cast<T>(new_rva);
    }

    class RANDO_SECTION Section {
    public:
        // No default construction (sections should always have a module)
        Section() = delete;

        Section(const Module &mod, uintptr_t rva = 0, size_t size = 0)
            : m_module(mod),
            m_start(mod, rva, AddressSpace::RVA),
            m_end(mod, rva + size, AddressSpace::RVA),
            m_size(size) {
        }

        Section(const Module &mod, IMAGE_SECTION_HEADER *sec_ptr)
            : m_module(mod), m_start(mod), m_end(mod), m_size(0) {
            if (sec_ptr != nullptr) {
                m_size = sec_ptr->Misc.VirtualSize;
                m_start.Reset(m_module, sec_ptr->VirtualAddress, AddressSpace::RVA);
                m_end.Reset(m_module, sec_ptr->VirtualAddress + m_size, AddressSpace::RVA);
            }
        }

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

    RANDO_SECTION void ForAllRelocations(FunctionList*) const;

    inline RANDO_SECTION Section export_section() const {
        return Section(*this, m_export_section);
    }

    inline RANDO_SECTION const char *get_module_name() const {
        if (m_file_name == nullptr)
            get_file_name();
        return m_file_name;
    }

    RANDO_SECTION void add_relocation(const Relocation &reloc) const {
        m_relocs.append(reloc);
    }

    const Vector<Relocation> &relocations() const {
        return m_relocs;
    }

private:
    ModuleInfo *m_info;
    HANDLE m_handle;
    mutable char *m_file_name;
    UNICODE_STRING *m_name;
    IMAGE_DOS_HEADER *m_dos_hdr;
    IMAGE_NT_HEADERS *m_nt_hdr;
    IMAGE_SECTION_HEADER *m_sections;

    IMAGE_SECTION_HEADER *m_textrap_section = nullptr;
    IMAGE_SECTION_HEADER *m_reloc_section = nullptr;
    IMAGE_SECTION_HEADER *m_export_section = nullptr;

    inline RANDO_SECTION Address RVA2Address(DWORD rva) const {
        return Address(*this, rva, AddressSpace::RVA);
    }

    enum RandoState : DWORD {
        NOT_RANDOMIZED = 0, // This must be 0, to match the default
        RANDOMIZED = 1,
        CANT_RANDOMIZE = 2,
        SELF_RANDOMIZE = 3,
    };

    RANDO_SECTION void MarkRandomized(RandoState);

    void arch_init();

    void fixup_target_relocations(FunctionList*) const;

    void get_file_name() const;

private:
    // FIXME: this shouldn't be mutable, Module should be non-const
    mutable Vector<Relocation> m_relocs;

private:
    // Architecture-specific fields
#if RANDOLIB_IS_X86
#elif RANDOLIB_IS_X86_64
    ptrdiff_t seh_C_specific_handler_rva;
    ptrdiff_t seh_CxxFrameHandler3_rva;
#if 0
    // For now, we don't care about this handler
    ptrdiff_t seh_GSHandlerCheck_rva;
#endif
    ptrdiff_t seh_GSHandlerCheck_SEH_rva;
    ptrdiff_t seh_GSHandlerCheck_EH_rva;
#endif
};

}
#endif // __cplusplus
