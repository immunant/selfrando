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

os::Module::Relocation::Relocation(const os::Module &mod, const TrapReloc &reloc)
    : m_module(mod), m_orig_src_addr(mod.address_from_trap(reloc.address)),
      m_src_addr(mod.address_from_trap(reloc.address)), m_type(reloc.type),
      m_symbol_addr(mod.address_from_trap(reloc.symbol)), m_addend(reloc.addend) {
    m_has_symbol_addr = (reloc.symbol != 0); // FIXME: what if zero addresses are legit???
}

static inline bool is_patched_gotpcrel(os::BytePointer at_ptr,
                                                 ptrdiff_t addend) {
    // BFD-specific hack: BFD sometimes replaces instructions like
    // OP %reg, foo@GOTPCREL(%rip) with immediate address versions:
    // OP %reg, $foo
    return (addend == -4 && (at_ptr[-1] >> 6) == 0x3 &&
            (at_ptr[-2] == 0xc7 || at_ptr[-2] == 0xf7 || at_ptr[-2] == 0x81));
}

static inline bool is_patched_tls_get_addr_call(os::BytePointer at_ptr) {
    // TLS GD-IE or GD-LE transformation in gold:
    // replaces a call to __tls_get_addr with a
    // RAX-relative LEA instruction
    return (at_ptr[-12] == 0x64 && at_ptr[-11] == 0x48 &&
            at_ptr[-10] == 0x8b && at_ptr[-9]  == 0x04 &&
            at_ptr[-8]  == 0x25 && at_ptr[-3]  == 0x48 &&
            at_ptr[-2]  == 0x8d && at_ptr[-1]  == 0x80);
}

static inline bool is_pcrel_tlsxd(os::BytePointer at_ptr) {
    return at_ptr[-3] == 0x48 && at_ptr[-2] == 0x8d && at_ptr[-1] == 0x3d;
}

static inline bool is_pcrel_gottpoff(os::BytePointer at_ptr) {
    return (at_ptr[-2] == 0x8b || at_ptr[-2] == 0x03) && // MOV or ADD
           ((at_ptr[-1] & 0xc7) == 0x05);                // RIP-relative
}

static inline bool is_pcrel_gotpc_tlsdesc(os::BytePointer at_ptr) {
    return at_ptr[-3] == 0x48 && at_ptr[-1] == 0x05 &&
           (at_ptr[-2] == 0x8d || at_ptr[-2] == 0x8b);
}

os::BytePointer os::Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep RandoLib/TrapInfoCommonh.h in sync whenever a new
    // relocation requires a symbol and/or addend.

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
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCRELX:
    case R_X86_64_REX_GOTPCRELX:
        if (is_patched_gotpcrel(at_ptr, m_addend))
            return reinterpret_cast<os::BytePointer>(*reinterpret_cast<uint32_t*>(at_ptr));
        goto pcrel_reloc;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPC32:
        if (is_patched_tls_get_addr_call(at_ptr))
            return nullptr;
    pcrel_reloc:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_addr.to_ptr() - m_addend + *reinterpret_cast<int32_t*>(at_ptr);
    case R_X86_64_PC64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
        return m_orig_src_addr.to_ptr() - m_addend + *reinterpret_cast<int64_t*>(at_ptr);
    // TLS relocations may get mutated to other instructions
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
        if (is_pcrel_tlsxd(at_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTTPOFF:
        if (is_pcrel_gottpoff(at_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTPC32_TLSDESC:
        if (is_pcrel_gotpc_tlsdesc(at_ptr))
            goto pcrel_reloc;
        break;
    default:
        return nullptr;
    }
    return nullptr;
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
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCRELX:
    case R_X86_64_REX_GOTPCRELX:
        if (is_patched_gotpcrel(at_ptr, m_addend)) {
            *reinterpret_cast<uint32_t*>(at_ptr) = reinterpret_cast<uintptr_t>(new_target);
            return;
        }
        goto pcrel_reloc;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPC32:
        if (is_patched_tls_get_addr_call(at_ptr))
            break;
    pcrel_reloc:
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target + m_addend - at_ptr);
        break;
    case R_X86_64_PC64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
        // FIXME: check for overflow here???
        *reinterpret_cast<int64_t*>(at_ptr) = static_cast<int64_t>(new_target + m_addend - at_ptr);
        break;
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
        if (is_pcrel_tlsxd(at_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTTPOFF:
        if (is_pcrel_gottpoff(at_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTPC32_TLSDESC:
        if (is_pcrel_gotpc_tlsdesc(at_ptr))
            goto pcrel_reloc;
        break;
    default:
        os::API::DebugPrintf<1>("Unknown relocation: %d\n", m_type);
        RANDO_ASSERT(false);
        break;
    }
}

os::Module::Relocation::Type os::Module::Relocation::get_pointer_reloc_type() {
    return R_X86_64_64;
}

void os::Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                     const Module &module,
                                                     os::Module::Relocation::Callback callback,
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
    os::Module::Relocation reloc(module,
                                 module.address_from_ptr(*export_ptr + 1),
                                 R_X86_64_PC32, -4);
    (*callback)(reloc, callback_arg);
    *export_ptr += 6;
}

void os::Module::Relocation::fixup_entry_point(const Module &module,
                                               uintptr_t entry_point,
                                               uintptr_t target) {
    RANDO_ASSERT(*reinterpret_cast<uint8_t*>(entry_point) == 0xE9);
    os::Module::Relocation reloc(module,
                                 module.address_from_ptr(entry_point + 1),
                                 R_X86_64_PC32, -4);
    reloc.set_target_ptr(reinterpret_cast<os::BytePointer>(target));
}

void os::Module::preprocess_linker_stubs() {
    m_linker_stubs = 0;
}

void os::Module::relocate_linker_stubs(FunctionList *functions,
                                       os::Module::Relocation::Callback callback,
                                       void *callback_arg) const {
}
