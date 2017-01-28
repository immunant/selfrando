/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .textramp, "ax", %progbits
.globl _TRaP_textramp_anchor
.hidden _TRaP_textramp_anchor
.type _TRaP_textramp_anchor, %object
_TRaP_textramp_anchor:
1:
    jmp 1b

