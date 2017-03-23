/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

enum ExtraInfo : uint32_t {
    EXTRA_NONE = 0,
    EXTRA_SYMBOL = 0x1,
    EXTRA_ADDEND = 0x2,
    RELOC_IGNORE = 0x4, // Ignore this relocation
};

#ifndef RANDO_SECTION
#define RANDO_SECTION
#endif

static inline RANDO_SECTION
uint32_t RelocExtraInfo(unsigned type) {
#if RANDOLIB_IS_POSIX
#if RANDOLIB_IS_X86
#elif RANDOLIB_IS_X86_64
    switch (type) {
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPC32:
    case R_X86_64_GOTPCREL:
    // 32 bit signed PC relative offset to GOT
    // without REX prefix, relaxable.
    case 41: // R_X86_64_GOTPCRELX
    // 32 bit signed PC relative offset to GOT
    case 42: // R_X86_64_REX_GOTPCRELX
    case R_X86_64_TLSGD:
    case R_X86_64_TLSLD:
    case R_X86_64_GOTTPOFF:
    case R_X86_64_GOTPC32_TLSDESC:
    case R_X86_64_PC64:
    case R_X86_64_GOTPCREL64:
    case R_X86_64_GOTPC64:
        return EXTRA_ADDEND;

    case R_X86_64_TPOFF32:
    case R_X86_64_TPOFF64:
    case R_X86_64_DTPOFF32:
    case R_X86_64_DTPOFF64:
        return RELOC_IGNORE;
    };
#elif RANDOLIB_IS_ARM
    switch (type) {
    case 3:     // R_ARM_REL32
    case 24:    // R_ARM_GOTOFF32
    case 25:    // R_ARM_BASE_PREL
    case 41:    // R_ARM_TARGET2
    case 42:    // R_ARM_PREL31
    case 96:    // R_ARM_GOT_PREL
        return EXTRA_ADDEND;

    case 43:    // R_ARM_MOVW_ABS_NC
    case 44:    // R_ARM_MOVT_ABS
    case 47:    // R_ARM_THM_MOVW_ABS_NC
    case 48:    // R_ARM_THM_MOVT_ABS
        return EXTRA_SYMBOL | EXTRA_ADDEND;

    case R_ARM_GOT32:
        return RELOC_IGNORE;
    };
#elif RANDOLIB_IS_ARM64
    switch(type) {
    case R_AARCH64_PREL32:
    case R_AARCH64_PREL64:
        return EXTRA_ADDEND;

    case R_AARCH64_ADR_PREL_PG_HI21:
    case R_AARCH64_ADR_PREL_PG_HI21_NC:
    case R_AARCH64_ADD_ABS_LO12_NC:
    case R_AARCH64_LDST8_ABS_LO12_NC:
    case R_AARCH64_LDST16_ABS_LO12_NC:
    case R_AARCH64_LDST32_ABS_LO12_NC:
    case R_AARCH64_LDST64_ABS_LO12_NC:
    case R_AARCH64_LDST128_ABS_LO12_NC:
        return EXTRA_SYMBOL | EXTRA_ADDEND;

    case 312: // FIXME: R_AARCH64_LD64_GOT_LO12_NC
        return RELOC_IGNORE;
    };
#else
#assert "Invalid target architecture"
#endif
#elif RANDOLIB_IS_WIN32
#endif

    return EXTRA_NONE;
}

