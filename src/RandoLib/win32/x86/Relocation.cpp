/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
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
        *reinterpret_cast<uint32_t*>(m_src_ptr) = reinterpret_cast<uintptr_t>(new_target);
        break;
    case IMAGE_REL_I386_REL32:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(m_src_ptr) = static_cast<int32_t>(new_target - (m_src_ptr + sizeof(int32_t)));
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
