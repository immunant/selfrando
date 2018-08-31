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

#include <TrapInfo.h>

struct FunctionList;
struct Function;

#ifdef __cplusplus

namespace os {

class RANDO_SECTION Module : public ModuleBase<Module> {
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

    class RANDO_SECTION Address : public AddressBase<Address> {
    public:
        using ModuleBase<Module>::AddressBase<Address>::AddressBase;

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
    };

    class RANDO_SECTION Relocation : public RelocationBase<DWORD> {
    public:
        Relocation() = delete;

        template<typename Ptr>
        Relocation(const Module &mod, Ptr ptr, Type type)
            : RelocationBase(mod, ptr, type) {
        }

        Relocation(const os::Module &mod, const trap_reloc_t &reloc)
            : RelocationBase(mod, Address::from_trap(mod, reloc.address).to_ptr(),
                             API::assert_cast<DWORD>(reloc.type)) {
        }

        BytePointer get_target_ptr() const;
        void set_target_ptr(BytePointer);

        static Type get_pointer_reloc_type();

        static Type type_from_based(Type based_type);

        static void fixup_export_trampoline(BytePointer*, const Module&, FunctionList*);
    };

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
        functions->adjust_relocation(&rva_reloc);
        if (subtract_one)
            full_addr++;

        auto new_rva = full_addr - reinterpret_cast<uintptr_t>(m_handle);
        *rva = API::assert_cast<T>(new_rva);
    }

    class RANDO_SECTION Section : public SectionBase<Address> {
    public:
        Section(const Module &mod, uintptr_t rva = 0, size_t size = 0)
            : SectionBase(mod, rva, size, AddressSpace::RVA) { }

        Section(const Module &mod, IMAGE_SECTION_HEADER *sec_ptr)
            : SectionBase(mod, 0) {
            if (sec_ptr != nullptr) {
                m_size = sec_ptr->Misc.VirtualSize;
                m_start.reset(m_module, sec_ptr->VirtualAddress, AddressSpace::RVA);
                m_end.reset(m_module, sec_ptr->VirtualAddress + m_size, AddressSpace::RVA);
            }
        }

        RANDO_SECTION PagePermissions change_permissions(PagePermissions perms) const;
    };

    // FIXME: TrapInfo could be pre-computed, and accessed via a function
    typedef void(*ExecSectionCallback)(const Module&, const Section&, ::TrapInfo&, bool, void*);
    RANDO_SECTION void for_all_exec_sections(bool, ExecSectionCallback, void*);

    typedef void(*ModuleCallback)(Module&, void*);
    static RANDO_SECTION void for_all_modules(ModuleCallback, void*);

    RANDO_SECTION void for_all_relocations(FunctionList*) const;

    inline RANDO_SECTION Section export_section() const {
        return Section(*this, m_export_section);
    }

    inline RANDO_SECTION const char *get_module_name() const {
        if (m_file_name == nullptr)
            get_file_name();
        return m_file_name;
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

    RANDO_SECTION void mark_randomized(RandoState);

    void arch_init();

    void fixup_target_relocations(FunctionList*) const;

    void get_file_name() const;

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
