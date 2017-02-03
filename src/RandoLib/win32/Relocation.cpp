/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "..\OS.h"
#include "..\TrapInfo.h"

os::Module::Relocation::Relocation(const os::Module &mod, const TrapReloc &reloc)
    : m_module(mod), m_orig_src_addr(mod.address_from_trap(reloc.address)),
      m_src_addr(mod.address_from_trap(reloc.address)), m_type(reloc.type) { }

os::BytePointer os::Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep RandoLib/TrapInfoCommonh.h in sync whenever a new
    // relocation requires a symbol and/or addend.

    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case IMAGE_REL_I386_DIR32:
    case IMAGE_REL_I386_DIR32NB: // FIXME: is this correct???
        return reinterpret_cast<os::BytePointer>(*reinterpret_cast<uint32_t*>(at_ptr));
    case IMAGE_REL_I386_REL32:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + *reinterpret_cast<int32_t*>(at_ptr);
    default:
        return nullptr;
    }
}

void os::Module::Relocation::set_target_ptr(os::BytePointer new_target) {
    auto at_ptr = m_src_addr.to_ptr();
    switch(m_type) {
    case IMAGE_REL_I386_DIR32:
    case IMAGE_REL_I386_DIR32NB:
        *reinterpret_cast<uint32_t*>(at_ptr) = reinterpret_cast<uintptr_t>(new_target);
        break;
    case IMAGE_REL_I386_REL32:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t)));
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
}

os::Module::Relocation::Type os::Module::Relocation::get_pointer_reloc_type() {
    return IMAGE_REL_I386_DIR32;
}

void os::Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                     const Module &module,
                                                     os::Module::Relocation::Callback callback,
                                                     void *callback_arg) {
    RANDO_ASSERT(**export_ptr == 0xE9);
    os::Module::Relocation reloc(module,
                                 module.address_from_ptr(*export_ptr + 1),
                                 IMAGE_REL_I386_REL32);
    (*callback)(reloc, callback_arg);
    *export_ptr += 5;
}
