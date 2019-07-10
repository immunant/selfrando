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

#include <asm/unistd.h>

#include <elf.h>

namespace os {

static inline bool is_patched_gotpcrel(BytePointer at_ptr,
                                       ptrdiff_t addend) {
    // BFD-specific hack: BFD sometimes replaces instructions like
    // OP %reg, foo@GOTPCREL(%rip) with immediate address versions:
    // OP %reg, $foo
    return (addend == -4 && (at_ptr[-1] >> 6) == 0x3 &&
            (at_ptr[-2] == 0xc7 || at_ptr[-2] == 0xf7 || at_ptr[-2] == 0x81));
}

static inline bool is_patched_tls_get_addr_call(BytePointer at_ptr) {
    // TLS GD-IE or GD-LE transformation in gold:
    // replaces a call to __tls_get_addr with a
    // RAX-relative LEA instruction
    // Bytes are: 64 48 8B 04 25 00 00 00 00 48 8D 80
    auto at_ptr32 = reinterpret_cast<uint32_t*>(at_ptr);
    return (at_ptr32[-3] == 0x048b4864 &&
            at_ptr32[-2] == 0x00000025 &&
            at_ptr32[-1] == 0x808d4800);
}

static inline bool is_pcrel_tlsxd(BytePointer at_ptr) {
    return at_ptr[-3] == 0x48 && at_ptr[-2] == 0x8d && at_ptr[-1] == 0x3d;
}

static inline bool is_pcrel_gottpoff(BytePointer at_ptr) {
    return (at_ptr[-2] == 0x8b || at_ptr[-2] == 0x03) && // MOV or ADD
           ((at_ptr[-1] & 0xc7) == 0x05);                // RIP-relative
}

static inline bool is_pcrel_gotpc_tlsdesc(BytePointer at_ptr) {
    return at_ptr[-3] == 0x48 && at_ptr[-1] == 0x05 &&
           (at_ptr[-2] == 0x8d || at_ptr[-2] == 0x8b);
}

BytePointer Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep TrapInfo/TrapInfoRelocs.h in sync whenever a new
    // relocation requires a symbol and/or addend.
    switch(m_type) {
    case R_X86_64_32:
    case R_X86_64_32S: // FIXME: is this correct???
        return reinterpret_cast<BytePointer>(*reinterpret_cast<uint32_t*>(m_src_ptr));
    case R_X86_64_64:
        return reinterpret_cast<BytePointer>(*reinterpret_cast<uint64_t*>(m_src_ptr));
    case R_X86_64_GOT64:
    case R_X86_64_GOTOFF64:
        return m_module.get_got_ptr() + *reinterpret_cast<ptrdiff_t*>(m_src_ptr);
    case R_X86_64_GOTPCREL:
    case 41: // R_X86_64_GOTPCRELX
    case 42: // R_X86_64_REX_GOTPCRELX
        if (is_patched_gotpcrel(m_src_ptr, m_addend))
            return reinterpret_cast<BytePointer>(*reinterpret_cast<uint32_t*>(m_src_ptr));
        if (m_src_ptr[-2] == 0xe9 && m_src_ptr[3] == 0x90) {
            // JMP *foo@GOTPCREL(%rip) got converted to JMP foo
            // which moved our relocation back 1 byte
            return (m_orig_src_ptr - 1) - m_addend +
                *reinterpret_cast<int32_t*>(m_src_ptr - 1);
        }
        goto pcrel_reloc;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPC32:
        if (is_patched_tls_get_addr_call(m_src_ptr))
            return nullptr;
    pcrel_reloc:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_ptr - m_addend + *reinterpret_cast<int32_t*>(m_src_ptr);
    case R_X86_64_PC64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
        return m_orig_src_ptr - m_addend + *reinterpret_cast<int64_t*>(m_src_ptr);
    // TLS relocations may get mutated to other instructions
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
        if (is_pcrel_tlsxd(m_src_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTTPOFF:
        if (is_pcrel_gottpoff(m_src_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTPC32_TLSDESC:
        if (is_pcrel_gotpc_tlsdesc(m_src_ptr))
            goto pcrel_reloc;
        break;
    default:
        return nullptr;
    }
    return nullptr;
}

void Module::Relocation::set_target_ptr(BytePointer new_target) {
    switch(m_type) {
    case R_X86_64_32:
    case R_X86_64_32S: // FIXME: is this correct???
        set_p32(new_target);
        break;
    case R_X86_64_64:
        set_p64(new_target);
        break;
    case R_X86_64_GOT64:
    case R_X86_64_GOTOFF64:
        set_i64(new_target - m_module.get_got_ptr());
        break;
    case R_X86_64_GOTPCREL:
    case 41: // R_X86_64_GOTPCRELX
    case 42: // R_X86_64_REX_GOTPCRELX
        if (is_patched_gotpcrel(m_src_ptr, m_addend)) {
            set_p32(new_target);
            return;
        }
        if (m_src_ptr[-2] == 0xe9 && m_src_ptr[3] == 0x90) {
            // See discussion in get_target_ptr()
            auto adj_src_ptr = m_src_ptr - 1;
            auto new_offset = new_target + m_addend - adj_src_ptr;
            *reinterpret_cast<int32_t*>(adj_src_ptr) =
                API::assert_cast<int32_t>(new_offset);
            return;
        }
        goto pcrel_reloc;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPC32:
        if (is_patched_tls_get_addr_call(m_src_ptr))
            break;
    pcrel_reloc:
        set_i32(new_target + m_addend - m_src_ptr);
        break;
    case R_X86_64_PC64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
        set_i64(new_target + m_addend - m_src_ptr);
        break;
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
        if (is_pcrel_tlsxd(m_src_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTTPOFF:
        if (is_pcrel_gottpoff(m_src_ptr))
            goto pcrel_reloc;
        break;
    case R_X86_64_GOTPC32_TLSDESC:
        if (is_pcrel_gotpc_tlsdesc(m_src_ptr))
            goto pcrel_reloc;
        break;
    default:
        API::debug_printf<1>("Unknown relocation: %d\n", m_type);
        RANDO_ASSERT(false);
        break;
    }
}

BytePointer Module::Relocation::get_got_entry() const {
    // IMPORTANT: Keep TrapInfo/TrapInfoRelocs.h in sync whenever a new
    // relocation requires a symbol and/or addend.
    auto at_ptr = m_src_ptr;
    switch(m_type) {
    case R_X86_64_GOT32:
        return m_module.get_got_ptr() + *reinterpret_cast<int32_t*>(at_ptr) - m_addend;
    case R_X86_64_GOT64:
    case R_X86_64_GOTPLT64:
        return m_module.get_got_ptr() + *reinterpret_cast<int64_t*>(at_ptr) - m_addend;
    case R_X86_64_GOTPCREL:
    case 41: // R_X86_64_GOTPCRELX
    case 42: // R_X86_64_REX_GOTPCRELX
        if (is_patched_gotpcrel(at_ptr, m_addend))
            return nullptr;
        if (at_ptr[-2] == 0x8d)
            return nullptr; // MOV-to-LEA conversion
        if (at_ptr[-2] == 0x67 && at_ptr[-1] == 0xe8)
            return nullptr; // callq-to-addr32-callq conversion
        if (at_ptr[-2] == 0xe9 && at_ptr[3] == 0x90)
            return nullptr; // jmpq-to-jmpq-nop conversion
        return at_ptr + *reinterpret_cast<int32_t*>(at_ptr) - m_addend;
    case R_X86_64_GOTPC32:
        at_ptr += *reinterpret_cast<int32_t*>(at_ptr) - m_addend;
        RANDO_ASSERT(at_ptr == m_module.get_got_ptr());
        return nullptr;
    case R_X86_64_GOTPCREL64:
        return at_ptr + *reinterpret_cast<int64_t*>(at_ptr) - m_addend;
    case R_X86_64_GOTPC64:
        at_ptr += *reinterpret_cast<int64_t*>(at_ptr);
        RANDO_ASSERT(at_ptr == m_module.get_got_ptr());
        return nullptr;
    default:
        return nullptr;
    }
}

Module::Relocation::Type Module::Relocation::get_pointer_reloc_type() {
    return R_X86_64_64;
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
    Module::Relocation reloc(module, *export_ptr + 1, R_X86_64_PC32, -4);
    functions->adjust_relocation(&reloc);
    *export_ptr += 6;
}

void Module::Relocation::fixup_entry_point(const Module &module,
                                           uintptr_t entry_point,
                                           uintptr_t target) {
    RANDO_ASSERT(*reinterpret_cast<uint8_t*>(entry_point) == 0xE9);
    Module::Relocation reloc(module, entry_point + 1, R_X86_64_PC32, -4);
    reloc.set_target_ptr(reinterpret_cast<BytePointer>(target));
}

void Module::preprocess_arch() {
    m_linker_stubs = 0;
}

void Module::relocate_arch(FunctionList *functions) const {
#if RANDOLIB_IS_POSIX
    if (m_module_info->trap_end_page != 0) {
        // If we built with --traplinker-selfrando-txtrp-pages,
        // putting all TRaP info and our own code together
        // in one contiguous .txtrp section, we can remove it from memory
        // after randomization. We do that using the munmap() syscall,
        // but we also want the syscall itself to disappear.
        // To do that, we put the syscall sequence at the very end of
        // .txtrp, so that the instruction immediately after the syscall
        // is on the next page and can execute normally after the kernel
        // returns. The instructions look something like this:
        //    ... <rest of .txtrp>
        //    MOV trap_start,  RDI
        //    MOV trap_size,   RSI
        //    MOV __NR_munmap, RAX
        //    SYSCALL
        //    ------- end of last .txtrp page
        // _TRaP_trap_end_page:
        //    RET
        auto end_page = m_module_info->trap_end_page;
        RANDO_ASSERT((end_page & (kPageSize - 1)) == 0);

        auto end_page_ptr = reinterpret_cast<BytePointer>(end_page);
        RANDO_ASSERT(end_page_ptr[0] == 0xC3);

        static const char kRemoveBytes[] =
            "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00" // MOV trap_start,  RDI
            "\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00" // MOV trap_size,   RSI
            "\xB8\x00\x00\x00\x00"                     // MOV __NR_munmap, RAX
            "\x0F\x05";                                // SYSCALL
        static constexpr size_t kRemoveBytesSize = sizeof(kRemoveBytes) - 1;
        auto remove_code = end_page_ptr - kRemoveBytesSize;
        API::memcpy(remove_code, kRemoveBytes, kRemoveBytesSize);

        // FIXME: this assumes that the start of .txtrp is always in
        // sections[0].trap
        auto trap_start = m_module_info->sections[0].trap;
        auto trap_pages = end_page - trap_start;
        *reinterpret_cast<uint64_t*>(remove_code +  2) = trap_start;
        *reinterpret_cast<uint64_t*>(remove_code + 12) = trap_pages;
        *reinterpret_cast<uint32_t*>(remove_code + 21) = __NR_munmap;

        // Patch the NOP at selfrando_remove_call to call remove_code
        auto remove_call = reinterpret_cast<BytePointer>(
            m_module_info->selfrando_remove_call);
        RANDO_ASSERT(remove_call[0] == 0x0F &&
                     remove_call[1] == 0x1F &&
                     remove_call[2] == 0x44);
        remove_call[0] = 0xE8;
        *reinterpret_cast<uint32_t*>(remove_call + 1) = (remove_code - (remove_call + 5));
    }
#endif
}

} // namespace os
