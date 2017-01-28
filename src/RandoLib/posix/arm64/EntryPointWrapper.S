/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .selfrando.entry, "ax", %progbits
.globl _TRaP_Linux_EntryPoint_init
.hidden _TRaP_Linux_EntryPoint_init
.type _TRaP_Linux_EntryPoint_init,%function
_TRaP_Linux_EntryPoint_init:
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!

    bl _TRaP_Linux_EntryPointImpl

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16

    b _TRaP_Linux_EntryPoint_init

.globl _TRaP_Linux_EntryPoint_entry
.hidden _TRaP_Linux_EntryPoint_entry
.type _TRaP_Linux_EntryPoint_entry,%function
_TRaP_Linux_EntryPoint_entry:
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!

    bl _TRaP_Linux_EntryPointImpl

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16

    b _TRaP_Linux_EntryPoint_entry

.globl _TRaP_Linux_EntryPoint_return
.hidden _TRaP_Linux_EntryPoint_return
.type _TRaP_Linux_EntryPoint_return,%function
_TRaP_Linux_EntryPoint_return:
    ret

