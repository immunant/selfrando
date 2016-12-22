/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "OS.h"
#include "TrapInfo.h"

#include <elf.h>

#define R_386_ADDN_EH_FRAME_HDR 0xffff0001

os::Module::Relocation::Relocation(const os::Module &mod, const TrapReloc &reloc, bool is_exec)
    : m_module(mod), m_orig_src_addr(mod.address_from_trap(reloc.address)),
      m_src_addr(mod.address_from_trap(reloc.address)), m_type(reloc.type),
      m_symbol_addr(mod.address_from_trap(reloc.symbol)), m_addend(reloc.addend), m_is_exec(is_exec) {
    m_has_symbol_addr = (reloc.symbol != 0); // FIXME: what if zero addresses are legit???
}

os::BytePointer os::Module::Relocation::get_target_ptr() const {
    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case R_386_32:
    case R_386_GOT32:
    case R_386_GOT32X:
    case R_386_TLS_LDO_32:
    case R_386_TLS_LDM:
    case R_386_TLS_GD:
        return reinterpret_cast<os::BytePointer>(*reinterpret_cast<uint32_t*>(at_ptr));
    case R_386_GOTOFF:
        return m_module.get_got_ptr() + *reinterpret_cast<ptrdiff_t*>(at_ptr);
    case R_386_PC32:
    case R_386_PLT32:
    case R_386_GOTPC:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_addr.to_ptr() + m_is_exec * sizeof(int32_t) + *reinterpret_cast<int32_t*>(at_ptr);
    case R_386_ADDN_EH_FRAME_HDR:
        return m_module.m_eh_frame_hdr + *reinterpret_cast<int32_t*>(at_ptr);
    default:
        return nullptr;
    }
}

void os::Module::Relocation::set_target_ptr(os::BytePointer new_target) {
    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case R_386_32:
    case R_386_GOT32:
    case R_386_GOT32X:
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
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + m_is_exec * sizeof(int32_t)));
        break;
    case R_386_ADDN_EH_FRAME_HDR:
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - m_module.m_eh_frame_hdr);
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
}

os::Module::Relocation::Type os::Module::Relocation::get_pointer_reloc_type() {
    return R_386_32;
}

os::Module::Relocation::Type os::Module::Relocation::get_eh_frame_reloc_type() {
    return R_386_ADDN_EH_FRAME_HDR;
}

void os::Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                     const Module &module,
                                                     os::Module::Relocation::Callback callback,
                                                     void *callback_arg) {
    RANDO_ASSERT(**export_ptr == 0xE9);
    os::Module::Relocation reloc(module,
                                 module.address_from_ptr(*export_ptr + 1),
                                 R_386_PC32);
    (*callback)(reloc, callback_arg);
    *export_ptr += 5;
}

uint32_t os::Module::Relocation::get_extra_info(os::Module::Relocation::Type type) {
    return 0;
}
