/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <TrapPlatform.h>

typedef enum {
    TRAP_RELOC_NONE   = 0,
    TRAP_RELOC_SYMBOL = 0x1,
    TRAP_RELOC_ADDEND = 0x2,
    TRAP_RELOC_IGNORE = 0x4, // Ignore this relocation

    // ARM64-specific relocs
    TRAP_RELOC_ARM64_GOT_PAGE  = 0x10000,
    TRAP_RELOC_ARM64_GOT_GROUP = 0x20000,
} trap_reloc_info_t;

#ifndef RANDO_SECTION
#define RANDO_SECTION
#endif

static inline RANDO_SECTION
uint64_t trap_reloc_info(uint64_t type, trap_platform_t platform) {
    switch (platform) {
    case TRAP_PLATFORM_POSIX_X86:
        switch (type) {
        case  2:    // R_386_PC32
        case  4:    // R_386_PLT32
        case 10:    // R_386_GOTPC
            return TRAP_RELOC_ADDEND;

        // None of the TLS relocations are PC-relative
        // or reference functions on x86, so ignore them
        case 14:    // R_386_TLS_TPOFF
        case 15:    // R_386_TLS_IE
        case 16:    // R_386_TLS_GOTIE
        case 17:    // R_386_TLS_LE
        case 18:    // R_386_TLS_GD
        case 19:    // R_386_TLS_LDM
        case 32:    // R_386_TLS_LDO_32
        case 33:    // R_386_TLS_IE_32
        case 34:    // R_386_TLS_LE_32
        case 35:    // R_386_DTPMOD32
        case 36:    // R_386_DTPOFF32
        case 37:    // R_386_TPOFF32
        case 39:    // R_386_TLS_GOTDESC
        case 40:    // R_386_TLS_DESC_CALL
        case 41:    // R_386_TLS_DESC
            return TRAP_RELOC_IGNORE;
        }
        return TRAP_RELOC_NONE;

    case TRAP_PLATFORM_POSIX_X86_64:
        switch (type) {
        case  2:    // R_X86_64_PC32
        case  3:    // R_X86_64_GOT32
        case  4:    // R_X86_64_PLT32
        case  9:    // R_X86_64_GOTPCREL
        case 19:    // R_X86_64_TLSGD
        case 20:    // R_X86_64_TLSLD
        case 22:    // R_X86_64_GOTTPOFF
        case 24:    // R_X86_64_PC64
        case 26:    // R_X86_64_GOTPC32
        case 27:    // R_X86_64_GOT64
        case 28:    // R_X86_64_GOTPCREL64
        case 29:    // R_X86_64_GOTPC64
        case 30:    // R_X86_64_GOTPLT64
        case 34:    // R_X86_64_GOTPC32_TLSDESC
        // 32 bit signed PC relative offset to GOT
        // without REX prefix, relaxable.
        case 41:    // R_X86_64_GOTPCRELX
        // 32 bit signed PC relative offset to GOT
        case 42:    // R_X86_64_REX_GOTPCRELX
            return TRAP_RELOC_ADDEND;

        case 17:    // R_X86_64_DTPOFF64
        case 18:    // R_X86_64_TPOFF64
        case 21:    // R_X86_64_DTPOFF32
        case 23:    // R_X86_64_TPOFF32
            return TRAP_RELOC_IGNORE;
        }
        return TRAP_RELOC_NONE;

    case TRAP_PLATFORM_POSIX_ARM:
        switch (type) {
        case 3:     // R_ARM_REL32
        case 24:    // R_ARM_GOTOFF32
        case 25:    // R_ARM_BASE_PREL
        case 26:    // R_ARM_GOT32 == R_ARM_GOT_BREL
        case 41:    // R_ARM_TARGET2
        case 42:    // R_ARM_PREL31
        case 96:    // R_ARM_GOT_PREL
            return TRAP_RELOC_ADDEND;

        case 43:    // R_ARM_MOVW_ABS_NC
        case 44:    // R_ARM_MOVT_ABS
        case 47:    // R_ARM_THM_MOVW_ABS_NC
        case 48:    // R_ARM_THM_MOVT_ABS
            return TRAP_RELOC_SYMBOL | TRAP_RELOC_ADDEND;
        }
        return TRAP_RELOC_NONE;

    case TRAP_PLATFORM_POSIX_ARM64:
        switch(type) {
        case 260: // R_AARCH64_PREL64
        case 261: // R_AARCH64_PREL32
            return TRAP_RELOC_ADDEND;

        case 263: // R_AARCH64_MOVW_UABS_G0
        case 264: // R_AARCH64_MOVW_UABS_G0_NC
        case 265: // R_AARCH64_MOVW_UABS_G1
        case 266: // R_AARCH64_MOVW_UABS_G1_NC
        case 267: // R_AARCH64_MOVW_UABS_G2
        case 268: // R_AARCH64_MOVW_UABS_G2_NC
        case 269: // R_AARCH64_MOVW_UABS_G3
        case 275: // R_AARCH64_ADR_PREL_PG_HI21
        case 276: // R_AARCH64_ADR_PREL_PG_HI21_NC
        case 277: // R_AARCH64_ADD_ABS_LO12_NC
        case 278: // R_AARCH64_LDST8_ABS_LO12_NC
        case 284: // R_AARCH64_LDST16_ABS_LO12_NC
        case 285: // R_AARCH64_LDST32_ABS_LO12_NC
        case 286: // R_AARCH64_LDST64_ABS_LO12_NC
        case 299: // R_AARCH64_LDST128_ABS_LO12_NC
            return TRAP_RELOC_SYMBOL | TRAP_RELOC_ADDEND;

        // Relocations that contain some subset of the address
        // of this symbol's GOT entry; we collect all such relocations
        // for each symbol, and merge them together to obtain the full address
        case 300: // R_AARCH64_MOVW_GOTOFF_G0
        case 301: // R_AARCH64_MOVW_GOTOFF_G0_NC
            return TRAP_RELOC_ARM64_GOT_GROUP;

        case 311: // R_AARCH64_ADR_GOT_PAGE
            return TRAP_RELOC_ARM64_GOT_PAGE;

        // This one doesn't need any extra information,
        // since we store everything we need in
        // the corresponding R_AARCH64_ADR_GOT_PAGE's entry
        case 302: // R_AARCH64_MOVW_GOTOFF_G1
        case 303: // R_AARCH64_MOVW_GOTOFF_G1_NC
        case 304: // R_AARCH64_MOVW_GOTOFF_G2
        case 305: // R_AARCH64_MOVW_GOTOFF_G2_NC
        case 306: // R_AARCH64_MOVW_GOTOFF_G3
        case 309: // R_AARCH64_GOT_LD_PREL19
        case 310: // R_AARCH64_LD64_GOTOFF_LO15
        case 312: // R_AARCH64_LD64_GOT_LO12_NC
        case 313: // R_AARCH64_LD64_GOTPAGE_LO15
            return TRAP_RELOC_NONE;
        };
        return TRAP_RELOC_NONE;

    default:
        return TRAP_RELOC_NONE;
    }
}
