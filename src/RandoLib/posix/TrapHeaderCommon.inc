/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "TrapCommon.h"

#if RANDOLIB_IS_ARM64
// On ARM64, we encode addresses as PC-relative offsets
#define ARCH_PCREL_FLAG     0x80
#define ARCH_BASEREL_FLAG   0x00
#else
// On all other architectures, we encode addresses as base-rel
#define ARCH_PCREL_FLAG     0x00
#define ARCH_BASEREL_FLAG   0x04
#endif

.section .txtrp, "a", %progbits
.globl _TRaP_trap_begin
.hidden _TRaP_trap_begin
.type _TRaP_trap_begin, %object
.p2align TRAP_HEADER_ALIGNMENT
_TRaP_trap_begin:
// Version byte
.byte 0x01
// Flags byte 1
.byte (0x51 | ARCH_PCREL_FLAG)
// Flags byte 2
.byte (0x03 | ARCH_BASEREL_FLAG)
// Flags byte 3
.byte 0x00
// Pointer size
.byte RANDOLIB_ARCH_SIZE

// Symbols for other sections
DEFINE_SECTION_SYMBOL(_TRaP_xptramp_begin, .textramp, "ax", %progbits)
