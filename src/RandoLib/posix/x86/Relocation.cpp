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

Module::Relocation::Relocation(const Module &mod, const trap_reloc_t &reloc)
    : m_module(mod), m_orig_src_addr(mod.address_from_trap(reloc.address)),
      m_src_addr(mod.address_from_trap(reloc.address)), m_type(reloc.type),
      m_symbol_addr(mod.address_from_trap(reloc.symbol)), m_addend(reloc.addend) {
    m_has_symbol_addr = (reloc.symbol != 0); // FIXME: what if zero addresses are legit???
}

BytePointer Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep TrapInfo/TrapInfoRelocs.h in sync whenever a new
    // relocation requires a symbol and/or addend.

    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case R_386_32:
    case R_386_GOT32:
    case R_386_TLS_LDO_32:
    case R_386_TLS_LDM:
    case R_386_TLS_GD:
        return reinterpret_cast<BytePointer>(*reinterpret_cast<uint32_t*>(at_ptr));
    case R_386_GOTOFF:
        return m_module.get_got_ptr() + *reinterpret_cast<ptrdiff_t*>(at_ptr);
    case R_386_PC32:
    case R_386_PLT32:
    case R_386_GOTPC:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + *reinterpret_cast<int32_t*>(at_ptr);
    default:
        return nullptr;
    }
}

void Module::Relocation::set_target_ptr(BytePointer new_target) {
    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case R_386_32:
    case R_386_GOT32:
    case R_386_TLS_LDO_32:
    case R_386_TLS_LDM:
    case R_386_TLS_GD:
        *reinterpret_cast<uint32_t*>(at_ptr) = reinterpret_cast<uintptr_t>(new_target);
        break;
    case R_386_GOTOFF:
        *reinterpret_cast<ptrdiff_t*>(at_ptr) = new_target - m_module.get_got_ptr();
        break;
    case R_386_PC32:
    case R_386_PLT32:
    case R_386_GOTPC:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t)));
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
}

Module::Relocation::Type Module::Relocation::get_pointer_reloc_type() {
    return R_386_32;
}

void Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                 const Module &module,
                                                 Module::Relocation::Callback callback,
                                                 void *callback_arg) {
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
    (*callback)(reloc, callback_arg);
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

void Module::preprocess_arch() {
    m_linker_stubs = 0;
}

void Module::relocate_arch(FunctionList *functions,
                           Module::Relocation::Callback callback,
                           void *callback_arg) const {
}

} // namespace os
