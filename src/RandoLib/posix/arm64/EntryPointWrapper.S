/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .selfrando.entry, "ax", %progbits
.globl selfrando_init
.hidden selfrando_init
.type selfrando_init,%function
selfrando_init:
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!

    bl selfrando_run

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16

    b selfrando_init

.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,%function
selfrando_entry:
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!

    bl selfrando_run

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16

    b selfrando_entry

.globl selfrando_return
.hidden selfrando_return
.type selfrando_return,%function
selfrando_return:
    ret

