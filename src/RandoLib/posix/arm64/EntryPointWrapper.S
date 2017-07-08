/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .selfrando.entry, "ax", %progbits
.globl Linux_EntryPoint_init
.hidden Linux_EntryPoint_init
.type Linux_EntryPoint_init,%function
Linux_EntryPoint_init:
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!

    bl Linux_EntryPointImpl

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16

    b Linux_EntryPoint_init

.globl Linux_EntryPoint_entry
.hidden Linux_EntryPoint_entry
.type Linux_EntryPoint_entry,%function
Linux_EntryPoint_entry:
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!

    bl Linux_EntryPointImpl

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16

    b Linux_EntryPoint_entry

.globl Linux_EntryPoint_return
.hidden Linux_EntryPoint_return
.type Linux_EntryPoint_return,%function
Linux_EntryPoint_return:
    ret

