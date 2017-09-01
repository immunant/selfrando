/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .txtrp, "ax", %progbits
.p2align 12
.globl trap_end_page
.hidden trap_end_page
.type trap_end_page, %object
trap_end_page:
    ret
