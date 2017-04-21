/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .txtrp, "a", %progbits

.globl _TRaP_trap_begin
.hidden _TRaP_trap_begin
.type _TRaP_trap_begin, %object
.p2align 12
_TRaP_trap_begin:
.byte 0x01 // Version
.byte 0xD1, 0x03, 0x00 // Flags
.byte RANDOLIB_ARCH_SIZE

