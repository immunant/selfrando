/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .txtrp, "ax", %progbits
.p2align 12
.globl  _TRaP_trap_end_page
.hidden _TRaP_trap_end_page
.type   _TRaP_trap_end_page, %object
_TRaP_trap_end_page:
    // FIXME: implement this
    udf
