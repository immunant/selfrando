/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>
#include <RandoLib.h>
#include <TrapInfo.h>

os::BytePointer os::Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep TrapInfo/TrapInfoRelocs.h in sync whenever a new
    // relocation requires a symbol and/or addend.
    switch(m_type) {
    case IMAGE_REL_I386_DIR32:
    case IMAGE_REL_I386_DIR32NB: // FIXME: is this correct???
        return reinterpret_cast<os::BytePointer>(*reinterpret_cast<uint32_t*>(m_src_ptr));
    case IMAGE_REL_I386_REL32:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_ptr + sizeof(int32_t) + *reinterpret_cast<int32_t*>(m_src_ptr);
    default:
        return nullptr;
    }
}

void os::Module::Relocation::set_target_ptr(os::BytePointer new_target) {
    switch(m_type) {
    case IMAGE_REL_I386_DIR32:
    case IMAGE_REL_I386_DIR32NB:
        set_p32(new_target);
        break;
    case IMAGE_REL_I386_REL32:
        set_i32(new_target - (m_src_ptr + sizeof(int32_t)));
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
}

os::Module::Relocation::Type os::Module::Relocation::get_pointer_reloc_type() {
    return IMAGE_REL_I386_DIR32;
}

os::Module::Relocation::Type
os::Module::Relocation::type_from_based(os::Module::Relocation::Type based_type) {
    if (based_type == IMAGE_REL_BASED_ABSOLUTE)
        return 0;
    if (based_type == IMAGE_REL_BASED_HIGHLOW)
        return IMAGE_REL_I386_DIR32;

    API::debug_printf<1>("Unknown relocation type: %d\n", (int) based_type);
    return 0;
}

void os::Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                     const Module &module,
                                                     FunctionList *functions) {
    RANDO_ASSERT(**export_ptr == 0xE9);
    os::Module::Relocation reloc(module, *export_ptr + 1, IMAGE_REL_I386_REL32);
    functions->adjust_relocation(&reloc);
    *export_ptr += 5;
}

void os::Module::arch_init() {
}

static RANDO_SECTION int compare_first_dword(const void *pa, const void *pb) {
    auto *fa = reinterpret_cast<const DWORD*>(pa);
    auto *fb = reinterpret_cast<const DWORD*>(pb);
    return (fa[0] < fb[0]) ? -1 : 1;
}

void os::Module::fixup_target_relocations(FunctionList *functions) const {
    for (size_t i = 0; i < functions->num_elems; i++) {
        auto &func = functions->elems[i];
        if (func.from_trap)
            continue;
        RANDO_ASSERT(func.is_gap); // Functions should either be from TRaP info or gaps

        auto div_ptr = func.div_start;
        auto undiv_ptr = func.undiv_start;
        // Look for PC-relative indirect branches
        // FIXME: we do this to find the 6-byte import trampolines
        // inserted by the linker; they're not in TRaP info, so
        // we need to scan for them manually.
        // WARNING!!!: we may get false positives
        for (;;) {
            while (div_ptr < func.div_end() &&
                (div_ptr[0] == 0xCC || div_ptr[0] == 0x90))
                div_ptr++, undiv_ptr++;
            if (div_ptr + 6 <= func.div_end() &&
                div_ptr[0] == 0xFF && div_ptr[1] == 0x25) {
                os::API::debug_printf<10>("Found import trampoline @%p/%p\n",
                                          undiv_ptr, div_ptr);
                // Absolute address, no REL32 relocation here,
                // but we do need to skip over it
                div_ptr += 6;
                undiv_ptr += 6;
                continue;
            }
            if (div_ptr + 10 <= func.div_end() &&
                div_ptr[0] == 0xB8 && div_ptr[5] == 0xE9) {
                // Delay-loading trampoline with contents:
                //   B8 nn nn nn nn         MOV EAX, [nnnnnnnn]
                //   E9 nn nn nn nn         JMP __tailMerge_NNN_dll
                os::API::debug_printf<10>("Found delay-loading import trampoline @%p/%p\n",
                                          undiv_ptr, div_ptr);
                os::Module::Relocation reloc(*this, undiv_ptr + 6, IMAGE_REL_I386_REL32);
                functions->adjust_relocation(&reloc);
                div_ptr += 10;
                undiv_ptr += 10;
                continue;
            }
            if (div_ptr + 17 <= func.div_end() &&
                div_ptr[0] == 0x51 && div_ptr[1] == 0x52 &&
                div_ptr[2] == 0x50 && div_ptr[3] == 0x68 &&
                div_ptr[8] == 0xE8 && div_ptr[13] == 0x5A &&
                div_ptr[14] == 0x59 && div_ptr[15] == 0xFF &&
                div_ptr[16] == 0xE0) {
                // __tailMerge_NNN_dll import trampoline with contents:
                //   51                     PUSH ECX
                //   52                     PUSH EDX
                //   50                     PUSH EAX
                //   68 nn nn nn nn         PUSH [nnnnnnnn]
                //   E8 nn nn nn nn         CALL __delayLoadHelper2@8
                //   5A                     POP EDX
                //   59                     POP ECX
                //   FF E0                  JMP EAX
                os::API::debug_printf<10>("Found __tailMerge import trampoline @%p/%p\n",
                                          undiv_ptr, div_ptr);
                os::Module::Relocation reloc(*this, undiv_ptr + 9, IMAGE_REL_I386_REL32);
                functions->adjust_relocation(&reloc);
                div_ptr += 17;
                undiv_ptr += 17;
                continue;
            }
            break;
        }
    }
    // Fix up exception handler table
    // FIXME: this seems to fix the Firefox SAFESEH-related crashes, but only partially
    // It is possible that the Windows loader makes a copy of this table at startup,
    // before we get to apply these relocations
    if (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG < m_nt_hdr->OptionalHeader.NumberOfRvaAndSizes) {
        auto &load_config_hdr = m_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (load_config_hdr.Size > 0) {
            auto *load_config = RVA2Address(load_config_hdr.VirtualAddress).to_ptr<IMAGE_LOAD_CONFIG_DIRECTORY*>();
            auto *seh_table = reinterpret_cast<BytePointer*>(load_config->SEHandlerTable);
            if (seh_table != nullptr && load_config->SEHandlerCount > 0) {
                auto table_size = load_config->SEHandlerCount * sizeof(BytePointer);
                for (size_t i = 0; i < load_config->SEHandlerCount; i++) {
                    relocate_rva(&seh_table[i], functions, false);
                }
                // Re-sort the SEH table
                os::API::qsort(seh_table, load_config->SEHandlerCount,
                               sizeof(BytePointer), compare_first_dword);
            }
        }
    }

}
