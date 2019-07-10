/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "TrapCommon.h"

.section .txtrp, "a", %progbits
.globl _TRaP_trap_begin
.hidden _TRaP_trap_begin
.type _TRaP_trap_begin, %object
.p2align TRAP_HEADER_ALIGNMENT
_TRaP_trap_begin:
// Version byte
.byte 0x01
// Flags byte 1
.byte 0xD1
// Flags byte 2
.byte 0x03
// Flags byte 3
.byte 0x00
// Pointer size
.byte RANDOLIB_ARCH_SIZE

// Symbols for other sections
DEFINE_SECTION_SYMBOL(_TRaP_xptramp_begin, .textramp, "ax", %progbits)
