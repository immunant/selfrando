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
#define R_X86_64_ADDN_EH_FRAME_HDR 0xffff0001

#ifndef R_X86_64_GOTPCRELX
#define R_X86_64_GOTPCRELX 41
#endif

#ifndef R_X86_64_REX_GOTPCRELX
#define R_X86_64_REX_GOTPCRELX 42
#endif


os::Module::Relocation::Relocation(const os::Module &mod, const TrapReloc &reloc, bool is_exec)
    : m_module(mod), m_orig_src_addr(mod.address_from_trap(reloc.address)),
      m_src_addr(mod.address_from_trap(reloc.address)), m_type(reloc.type),
      m_symbol_addr(mod.address_from_trap(reloc.symbol)), m_addend(reloc.addend), m_is_exec(is_exec) {
    m_has_symbol_addr = (reloc.symbol != 0); // FIXME: what if zero addresses are legit???
}

os::BytePointer os::Module::Relocation::get_target_ptr() const {
    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case R_X86_64_32:
    case R_X86_64_32S: // FIXME: is this correct???
        return reinterpret_cast<os::BytePointer>(*reinterpret_cast<uint32_t*>(at_ptr));
    case R_X86_64_64:
    case R_X86_64_GOT64:
        return reinterpret_cast<os::BytePointer>(*reinterpret_cast<uint64_t*>(at_ptr));
    case R_X86_64_GOTOFF64:
        return m_module.get_got_ptr() + *reinterpret_cast<ptrdiff_t*>(at_ptr);
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCRELX:
    case R_X86_64_REX_GOTPCRELX:
        if (m_has_symbol_addr)
            return m_symbol_addr.to_ptr();
    case R_X86_64_GOTPC32:
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
    case R_X86_64_GOTTPOFF:
    case R_X86_64_GOTPC32_TLSDESC:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_addr.to_ptr() + m_is_exec * sizeof(int32_t) + *reinterpret_cast<int32_t*>(at_ptr);
    case R_X86_64_PC64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
        return m_orig_src_addr.to_ptr() + m_is_exec * sizeof(int64_t) + *reinterpret_cast<int64_t*>(at_ptr);
    case R_X86_64_ADDN_EH_FRAME_HDR:
        return m_module.m_eh_frame_hdr + *reinterpret_cast<int32_t*>(at_ptr);
    default:
        return nullptr;
    }
}

void os::Module::Relocation::set_target_ptr(os::BytePointer new_target) {
    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case R_X86_64_32:
    case R_X86_64_32S: // FIXME: is this correct???
        *reinterpret_cast<uint32_t*>(at_ptr) = reinterpret_cast<uintptr_t>(new_target);
        break;
    case R_X86_64_64:
    case R_X86_64_GOT64:
        *reinterpret_cast<uint64_t*>(at_ptr) = reinterpret_cast<uintptr_t>(new_target);
        break;
    case R_X86_64_GOTOFF64:
        *reinterpret_cast<ptrdiff_t*>(at_ptr) = new_target - m_module.get_got_ptr();
        break;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCRELX:
    case R_X86_64_REX_GOTPCRELX:
        if (m_has_symbol_addr) {
            *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target + m_addend - at_ptr);
            break;
        }
    case R_X86_64_GOTPC32:
    case R_X86_64_TLSGD:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + m_is_exec * sizeof(int32_t)));
        break;
    case R_X86_64_PC64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
        // FIXME: check for overflow here???
        *reinterpret_cast<int64_t*>(at_ptr) = static_cast<int64_t>(new_target - (at_ptr + m_is_exec * sizeof(int64_t)));
        break;
    case R_X86_64_ADDN_EH_FRAME_HDR:
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - m_module.m_eh_frame_hdr);
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
}

os::Module::Relocation::Type os::Module::Relocation::get_pointer_reloc_type() {
    return R_X86_64_64;
}

os::Module::Relocation::Type os::Module::Relocation::get_eh_frame_reloc_type() {
    return R_X86_64_ADDN_EH_FRAME_HDR;
}

void os::Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                     const Module &module,
                                                     os::Module::Relocation::Callback callback,
                                                     void *callback_arg) {
    RANDO_ASSERT(**export_ptr == 0xE9);
    os::Module::Relocation reloc(module,
                                 module.address_from_ptr(*export_ptr + 1),
                                 R_X86_64_PC32);
    (*callback)(reloc, callback_arg);
    *export_ptr += 5;
}

uint32_t os::Module::Relocation::get_extra_info(os::Module::Relocation::Type type) {
    switch(type) {
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCRELX:
    case R_X86_64_REX_GOTPCRELX:
        return EXTRA_ADDEND;
    default:
        return 0;
    }
}
