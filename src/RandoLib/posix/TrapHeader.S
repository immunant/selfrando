/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .txtrp, "a", @progbits

.globl _TRaP_Info_txtrp
.type _TRaP_Info_txtrp, @object
_TRaP_Info_txtrp:
.byte 0x01 // Version
.byte 0x11, 0x00, 0x00 // Flags

