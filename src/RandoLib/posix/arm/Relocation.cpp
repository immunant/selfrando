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
#include <Utility.h>

#include "RelocTypes.h"

namespace os {

#define BIT(X, B) \
    ((X >> B) & 1)

// 0 bits of mask are from X, 1 bits from Y
#define BIT_SELECT(mask, X, Y)                  \
    (((X) & ~(mask)) | ((Y) & (mask)))

#define ALIGN(X, Y) \
    (reinterpret_cast<uint32_t>(X) & ~(static_cast<uint32_t>(Y)-1))

#define B_T1_get(ins)                                   \
    (signextend<int32_t, 12>((ins & 0x7ff) << 1))

#define B_T1_set(ins, dest)                                     \
    (BIT_SELECT(0x7ff, static_cast<uint16_t>(ins),              \
                ((dest & 0xffe) >> 1)))

#define B_T2_get(ins)                                   \
    (signextend<int32_t, 9>((ins & 0xff) << 1))

#define B_T2_set(ins, dest)                                     \
    (BIT_SELECT(0xff, static_cast<uint16_t>(ins),               \
                ((dest & 0x1fe) >> 1)))

#define imm24_get(ins)                                  \
    (signextend<int32_t, 26>((ins & 0xffffff) << 2))

#define imm24_set(ins, dest)                                    \
    (BIT_SELECT(0xffffff, ins,                                  \
                ((dest & 0x3ffffff) >> 2)))

inline int32_t thm_imm24_get(uint32_t ins) {
    auto S = BIT(ins, 10);
    auto I1 = BIT(ins, 29) ^ S ^ 1;
    auto I2 = BIT(ins, 27) ^ S ^ 1;
    auto value =
            (S << 24) | (I1 << 23) | (I2 << 22) |
            ((ins & 0x3ff) << 12) | ((ins & 0x7ff0000) >> 15);
    return signextend<int32_t, 25>(value);
}

inline int32_t thm_imm19_get(uint32_t ins) {
    auto S = BIT(ins, 10);
    auto J1 = BIT(ins, 29);
    auto J2 = BIT(ins, 27);
    auto value =
            (S << 20) | (J2 << 19) | (J1 << 18) |
            ((ins & 0x3f) << 12) | ((ins & 0x7ff0000) >> 15);
    return signextend<int32_t, 21>(value);
}

inline uint32_t thm_imm24_set(uint32_t ins, int32_t dest) {
    auto imm11 = (dest >> 1) & 0x7ff;
    auto imm10 = (dest >> 12) & 0x3ff;
    auto I2 = BIT(dest, 22);
    auto I1 = BIT(dest, 23);
    auto S = BIT(dest, 24);
    auto J1 = ((~I1) ^ S) & 1;
    auto J2 = ((~I2) ^ S) & 1;
    return BIT_SELECT(0x2fff07ff, ins,
                      (S << 10) | (J1 << 29) | (J2 << 27)
                      | imm10 | (imm11 << 16));
}

inline uint32_t thm_imm19_set(uint32_t ins, int32_t dest) {
    auto imm11 = (dest >> 1) & 0x7ff;
    auto imm6 = (dest >> 12) & 0x3f;
    auto S = BIT(dest, 20);
    auto J2 = BIT(dest, 19);
    auto J1 = BIT(dest, 18);
    return BIT_SELECT(0x2fff043f, ins,
                      (S << 10) | (J1 << 29) | (J2 << 27)
                      | imm6 | (imm11 << 16));
}

static inline bool arm_bl_isX(uint32_t ins) {
    return (ins & 0xfe000000) == 0xfa000000;
}

inline bool thm_bl_isX(uint32_t ins) {
    return BIT(ins, 28) ^ 1;
}

inline uint32_t movwt_set(uint32_t ins, uint32_t imm) {
    imm &= 0xffff;
    ins &= 0xfff0f000;
    ins |= (imm & 0x0fff);
    ins |= (imm & 0xf000) << 4;
    return ins;
}

inline uint32_t thm_movwt_set(uint32_t ins, uint32_t imm) {
    // FIXME: this assumes little-endian
    imm &= 0xffff;
    ins &= 0x8f00fbf0;
    ins |= (imm & 0xf000) >> 12;
    ins |= (imm & 0x0800) >> 1;
    ins |= (imm & 0x0700) << 20;
    ins |= (imm & 0x00ff) << 16;
    return ins;
}

BytePointer Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep TrapInfo/TrapInfoRelocs.h in sync whenever a new
    // relocation requires a symbol and/or addend.

    auto cur_address = m_src_ptr;
    auto reloc_contents = *reinterpret_cast<uint32_t*>(cur_address);
    auto orig_address = m_orig_src_ptr;
    switch(m_type) {
    // Data relocs
    case R_ARM_ABS32:
    case R_ARM_TARGET1: // The ARM exception handling ABI says this is equivalent to R_ARM_ABS32
        return reinterpret_cast<BytePointer>(reloc_contents & 0xfffffffe);
    case R_ARM_REL32:
    case R_ARM_GOTPC: // aka R_ARM_BASE_PREL
    case R_ARM_GOT_PREL:
    case R_ARM_TARGET2:
        return orig_address + *reinterpret_cast<int32_t*>(cur_address) - m_addend;
    case R_ARM_PREL31:
        return signextend<int32_t, 31>(reloc_contents & 0x7fffffff) + orig_address - m_addend;
    case R_ARM_GOTOFF:
        return m_module.get_got_ptr() + *reinterpret_cast<int32_t*>(cur_address) - m_addend;
    // Instruction relocs
    case R_ARM_CALL:
        if (arm_bl_isX(reloc_contents))
            return imm24_get(reloc_contents) + orig_address + 8 + ((reloc_contents >> 23) & 0x2);
    case R_ARM_JUMP24:
    case R_ARM_PLT32:
        return imm24_get(reloc_contents) + orig_address + 8;
    case R_ARM_THM_PC22:
        if (thm_bl_isX(reloc_contents))
            return thm_imm24_get(reloc_contents) + reinterpret_cast<BytePointer>(ALIGN(orig_address + 4, 4));
        // intentional fall-through
    case R_ARM_THM_JUMP24:
        return thm_imm24_get(reloc_contents) + orig_address + 4;
    case R_ARM_THM_JUMP19:
        return thm_imm19_get(reloc_contents) + orig_address + 4;
    case R_ARM_THM_PC11:
        return B_T1_get(*reinterpret_cast<uint16_t*>(cur_address)) + orig_address + 4;
    case R_ARM_THM_PC9:
        return B_T2_get(*reinterpret_cast<uint16_t*>(cur_address)) + orig_address + 4;
    case R_ARM_MOVW_ABS_NC:
    case R_ARM_THM_MOVW_ABS_NC:
    case R_ARM_MOVT_ABS:
    case R_ARM_THM_MOVT_ABS:
        RANDO_ASSERT(m_has_symbol_ptr);
        return m_symbol_ptr + m_addend;
    case R_ARM_GOT32:
        // Nothing to do here, we just need this for get_got_entry()
        return nullptr;
    default:
        RANDO_ASSERT(false);
        return nullptr;
    }
}

#define RANDO_ASSERT_DELTA_SIZE(bits, delta)        \
    do {                                            \
        ptrdiff_t max =  (1LL << ((bits) - 1)) - 1; \
        ptrdiff_t min = -(1LL << ((bits) - 1));     \
        RANDO_ASSERT((delta) <= max);               \
        RANDO_ASSERT((delta) >= min);               \
    } while (0)

void Module::Relocation::set_target_ptr(BytePointer new_target) {
    auto cur_address = m_src_ptr;
    auto reloc_contents = *reinterpret_cast<uint32_t*>(cur_address);
    ptrdiff_t        pcrel_delta = new_target - cur_address;
    ptrdiff_t addend_pcrel_delta = pcrel_delta + m_addend;
    switch(m_type) {
    case R_ARM_REL32:
    case R_ARM_GOTPC: // aka R_ARM_BASE_PREL
    case R_ARM_GOT_PREL:
    case R_ARM_TARGET2:
        *reinterpret_cast<int32_t*>(cur_address) = static_cast<int32_t>(addend_pcrel_delta);
        break;
    case R_ARM_PREL31:
        RANDO_ASSERT_DELTA_SIZE(31, addend_pcrel_delta);
        *reinterpret_cast<int32_t*>(cur_address) = static_cast<int32_t>(addend_pcrel_delta) & 0x7fffffff;
        break;
    case R_ARM_GOTOFF:
        *reinterpret_cast<int32_t*>(cur_address) = static_cast<int32_t>(new_target + m_addend - m_module.get_got_ptr());
        break;
    case R_ARM_THM_PC11:
        pcrel_delta -= 4;
        RANDO_ASSERT_DELTA_SIZE(12, pcrel_delta);
        *reinterpret_cast<uint16_t*>(cur_address) =
                B_T1_set(*reinterpret_cast<uint16_t*>(cur_address), pcrel_delta);
        break;
    case R_ARM_THM_PC9:
        pcrel_delta -= 4;
        RANDO_ASSERT_DELTA_SIZE(9, pcrel_delta);
        *reinterpret_cast<uint16_t*>(cur_address) =
                B_T2_set(*reinterpret_cast<uint16_t*>(cur_address), pcrel_delta);
        break;
    case R_ARM_THM_PC22:
        if (thm_bl_isX(reloc_contents)) {
            pcrel_delta = reinterpret_cast<ptrdiff_t>(new_target - ALIGN(cur_address + 4, 4));
            RANDO_ASSERT_DELTA_SIZE(25, pcrel_delta);
            *reinterpret_cast<uint32_t*>(cur_address) =
                    thm_imm24_set(reloc_contents, reinterpret_cast<int32_t>(pcrel_delta) & 0x01fffffe);
            break;
        }
        // intentional fall-through
    case R_ARM_THM_JUMP24:
        pcrel_delta -= 4;
        RANDO_ASSERT_DELTA_SIZE(25, pcrel_delta);
         *reinterpret_cast<uint32_t*>(cur_address) =
                thm_imm24_set(reloc_contents, reinterpret_cast<int32_t>(pcrel_delta) & 0x01fffffe);
        break;
    case R_ARM_THM_JUMP19:
        pcrel_delta -= 4;
        RANDO_ASSERT_DELTA_SIZE(21, pcrel_delta);
         *reinterpret_cast<uint32_t*>(cur_address) =
                thm_imm19_set(reloc_contents, reinterpret_cast<int32_t>(pcrel_delta) & 0x1ffffe);
        break;
    case R_ARM_CALL:
    case R_ARM_JUMP24:
    case R_ARM_PLT32: {
        bool is_blX = arm_bl_isX(reloc_contents);
        pcrel_delta -= 8;
        RANDO_ASSERT_DELTA_SIZE(26, pcrel_delta);
        *reinterpret_cast<uint32_t*>(cur_address) =
            imm24_set(reloc_contents, reinterpret_cast<int32_t>(pcrel_delta) & 0x03fffffe);
        if (m_type == R_ARM_CALL && is_blX) {
            // If the instruction is a BLX direct call, bit 24 of the
            // instruction encodes bit 1 of the offset
            if ((pcrel_delta & 0x2) != 0) {
                *reinterpret_cast<uint32_t*>(cur_address) |= 1 << 24;
            } else {
                *reinterpret_cast<uint32_t*>(cur_address) &= ~(1 << 24);
            }
        }
        break;
    }
    case R_ARM_ABS32:
    case R_ARM_TARGET1:
        *reinterpret_cast<uint32_t*>(cur_address) =
            BIT_SELECT(0xfffffffe, reloc_contents, reinterpret_cast<uint32_t>(new_target));
        break;
    case R_ARM_JUMP_SLOT:
        // Ignore these
        break;
    case R_ARM_MOVW_ABS_NC:
        if (m_has_symbol_ptr)
            *reinterpret_cast<uint32_t*>(cur_address) =
               movwt_set(*reinterpret_cast<uint32_t*>(cur_address), reinterpret_cast<uint32_t>(new_target));
        break;
    case R_ARM_MOVT_ABS:
        if (m_has_symbol_ptr)
            *reinterpret_cast<uint32_t*>(cur_address) =
               movwt_set(*reinterpret_cast<uint32_t*>(cur_address), reinterpret_cast<uint32_t>(new_target) >> 16);
        break;
    case R_ARM_THM_MOVW_ABS_NC:
        if (m_has_symbol_ptr)
            *reinterpret_cast<uint32_t*>(cur_address) =
               thm_movwt_set(*reinterpret_cast<uint32_t*>(cur_address), reinterpret_cast<uint32_t>(new_target));
        break;
    case R_ARM_THM_MOVT_ABS:
        if (m_has_symbol_ptr)
            *reinterpret_cast<uint32_t*>(cur_address) =
               thm_movwt_set(*reinterpret_cast<uint32_t*>(cur_address), reinterpret_cast<uint32_t>(new_target) >> 16);
        break;
    case R_ARM_GOT32:
        // Nothing to do here, we just need this for get_got_entry()
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
    API::debug_printf<5>("Setting reloc - target: %p, new contents: %p\n", new_target, *reinterpret_cast<uint32_t*>(cur_address));
}

BytePointer Module::Relocation::get_got_entry() const {
    auto at_ptr = m_src_ptr;
    switch(m_type) {
    case R_ARM_GOT32:
        return m_module.get_got_ptr() + *reinterpret_cast<int32_t*>(at_ptr) - m_addend;
    case R_ARM_GOT_PREL:
        return at_ptr + *reinterpret_cast<int32_t*>(at_ptr) - m_addend;
    default:
        return nullptr;
    }
}

Module::Relocation::Type Module::Relocation::get_pointer_reloc_type() {
    return R_ARM_ABS32;
}

void Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                 const Module &module,
                                                 FunctionList *functions) {
    unsigned int reloc_type;
    if (*((*export_ptr)+3) == 0xea) {
        API::debug_printf<5>("Export tramp (arm): %p\n", *export_ptr);
        reloc_type = R_ARM_JUMP24;
    } else {
        API::debug_printf<5>("Export tramp (thumb): %p\n", *export_ptr);
        reloc_type = R_ARM_THM_JUMP24;
    }
    Module::Relocation reloc(module, *export_ptr, reloc_type);
    functions->adjust_relocation(&reloc);
    *export_ptr += 4;
}

void Module::Relocation::fixup_entry_point(const Module &module,
                                           uintptr_t entry_point,
                                           uintptr_t target) {
    *reinterpret_cast<int32_t*>(entry_point - 4) =
        os::API::assert_cast<int32_t>(target - entry_point);
}

void Module::preprocess_arch() {
    m_linker_stubs = 0;
}

void Module::relocate_arch(FunctionList *functions) const {
    for (size_t i = 0; i < TRAP_NUM_SECTIONS; i++) {
        auto &sec_info = m_module_info->sections[i];
        if (sec_info.start == 0 || sec_info.size == 0 ||
            sec_info.trap  == 0 || sec_info.trap_size == 0)
            continue;

        Section sec(*this, sec_info.start, sec_info.size);
        for (size_t j = 0; j < functions->num_elems; j++) {
            auto &func = functions->elems[j];
            if (!sec.contains_addr(func.div_start))
                continue;
            if (func.skip_copy || func.from_trap)
                continue; // Functions described in TRaP info should have relocs
            auto undiv_ptr = reinterpret_cast<uint32_t*>(func.undiv_start);
            auto   div_ptr = reinterpret_cast<uint32_t*>(func.div_start);
            auto       end = reinterpret_cast<uint32_t*>(func.div_start + func.size);
            for (; div_ptr < end; undiv_ptr++, div_ptr++) {
                if (div_ptr[0] == 0x46c04778) {
                    // Found some Thumb stubs
                    API::debug_printf<10>("Found Thumb linker stub @%p/%p\n",
                                          undiv_ptr, div_ptr);
                    undiv_ptr++, div_ptr++;
                }
                switch(div_ptr[0]) {
                case 0xe51ff004: {
                    API::debug_printf<10>("Found ARM/Thumb linker stub A@%p/%p\n",
                                          undiv_ptr, div_ptr);
                    undiv_ptr += 1, div_ptr += 1;
                    Relocation reloc(*this, undiv_ptr, R_ARM_ABS32, 0);
                    functions->adjust_relocation(&reloc);
                    break;
                }
                case 0xe59fc000: {
                    RANDO_ASSERT(div_ptr[1] == 0xe12fff1c ||
                                 div_ptr[1] == 0xe08cf00f ||
                                 div_ptr[1] == 0xe08ff00c);
                    API::debug_printf<10>("Found ARM/Thumb linker stub B@%p/%p\n",
                                          undiv_ptr, div_ptr);
                    undiv_ptr += 2, div_ptr += 2;
                    if (div_ptr[-1] == 0xe12fff1c) {
                        Relocation reloc(*this, undiv_ptr, R_ARM_ABS32, 0);
                        functions->adjust_relocation(&reloc);
                    } else {
                        Relocation reloc(*this, undiv_ptr, R_ARM_REL32, -4);
                        functions->adjust_relocation(&reloc);
                    }
                    break;
                }
                case 0xe59fc004: {
                    API::debug_printf<10>("Found ARM/Thumb linker stub C@%p/%p\n",
                                          undiv_ptr, div_ptr);
                    RANDO_ASSERT(div_ptr[1] == 0xe08fc00c);
                    RANDO_ASSERT(div_ptr[2] == 0xe12fff1c);
                    undiv_ptr += 3, div_ptr += 3;
                    Relocation reloc(*this, undiv_ptr, R_ARM_REL32, 0);
                    functions->adjust_relocation(&reloc);
                    break;
                }
                default: {
                    if (div_ptr[-1] == 0x46c04778) {
                        RANDO_ASSERT((div_ptr[0] >> 24) == 0xea); // Make sure we're patching a B instruction
                        API::debug_printf<10>("Found Thumb short branch stub @%p/%p\n",
                                              undiv_ptr, div_ptr);
                        Relocation reloc(*this, undiv_ptr, R_ARM_JUMP24, -8);
                        functions->adjust_relocation(&reloc);
                        break;
                    }
                    if ((div_ptr[0] & 0xd000f800) == 0x9000f000) {
                        API::debug_printf<10>("Found A8 veneer stub @%p/%p\n",
                                              undiv_ptr, div_ptr);
                        Relocation reloc(*this, undiv_ptr, R_ARM_THM_JUMP24, -4);
                        functions->adjust_relocation(&reloc);
                        break;
                    }
                    break;
                }
                }
            }
        }
    }
}

} // namespace os
