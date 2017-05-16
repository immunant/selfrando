/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>
#include <TrapInfo.h>

#include <elf.h>

namespace os {

BytePointer Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep TrapInfo/TrapInfoRelocs.h in sync whenever a new
    // relocation requires a symbol and/or addend.
    switch(m_type) {
    case R_386_32:
    case R_386_TLS_LDO_32:
    case R_386_TLS_LDM:
    case R_386_TLS_GD:
        return reinterpret_cast<BytePointer>(*reinterpret_cast<uint32_t*>(m_src_ptr));
    case R_386_GOT32:
    case R_386_GOTOFF:
        return m_module.get_got_ptr() + *reinterpret_cast<ptrdiff_t*>(m_src_ptr);
    case R_386_PC32:
    case R_386_PLT32:
    case R_386_GOTPC:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_ptr + sizeof(int32_t) + *reinterpret_cast<int32_t*>(m_src_ptr);
    default:
        return nullptr;
    }
}

void Module::Relocation::set_target_ptr(BytePointer new_target) {
    switch(m_type) {
    case R_386_32:
    case R_386_TLS_LDO_32:
    case R_386_TLS_LDM:
    case R_386_TLS_GD:
        *reinterpret_cast<uint32_t*>(m_src_ptr) = reinterpret_cast<uintptr_t>(new_target);
        break;
    case R_386_GOT32:
    case R_386_GOTOFF:
        *reinterpret_cast<ptrdiff_t*>(m_src_ptr) = new_target - m_module.get_got_ptr();
        break;
    case R_386_PC32:
    case R_386_PLT32:
    case R_386_GOTPC:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(m_src_ptr) = static_cast<int32_t>(new_target - (m_src_ptr + sizeof(int32_t)));
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
}

BytePointer Module::Relocation::get_got_entry() const {
    switch(m_type) {
    // TODO: handle arch GOT relocations
    default:
        return nullptr;
    }
}

Module::Relocation::Type Module::Relocation::get_pointer_reloc_type() {
    return R_386_32;
}

void Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                 const Module &module,
                                                 FunctionList *functions) {
    if (**export_ptr == 0xEB) {
        // We hit the placeholder in Textramp.S, skip over it
        *export_ptr += 2;
        return;
    }
    // Allow the first byte of the export trampoline to be 0xCC, which
    // is the opcode for the breakpoint instruction that gdb uses (INT 3)
    RANDO_ASSERT(**export_ptr == 0xE9 || **export_ptr == 0xCC);
    RANDO_ASSERT((reinterpret_cast<uintptr_t>(*export_ptr) & 1) == 0);
    Module::Relocation reloc(module,
                             module.address_from_ptr(*export_ptr + 1),
                             R_386_PC32);
    functions->AdjustRelocation(&reloc);
    *export_ptr += 6;
}

void Module::Relocation::fixup_entry_point(const Module &module,
                                           uintptr_t entry_point,
                                           uintptr_t target) {
    RANDO_ASSERT(*reinterpret_cast<uint8_t*>(entry_point) == 0xE9);
    Module::Relocation reloc(module,
                             module.address_from_ptr(entry_point + 1),
                             R_386_PC32, -4);
    reloc.set_target_ptr(reinterpret_cast<BytePointer>(target));
}

template<>
size_t Module::arch_reloc_type<Elf32_Rel>(const Elf32_Rel *rel) {
    auto rel_type = ELF32_R_TYPE(rel->r_info);
    if (rel_type == R_386_RELATIVE ||
        rel_type == R_386_GLOB_DAT ||
        rel_type == R_386_32) {
        return R_386_32;
    }
    return 0;
}

void Module::preprocess_arch() {
    m_linker_stubs = 0;
    build_arch_relocs<Elf32_Dyn, Elf32_Rel, DT_REL, DT_RELSZ>();
}

void Module::relocate_arch(FunctionList *functions) const {
}

} // namespace os
