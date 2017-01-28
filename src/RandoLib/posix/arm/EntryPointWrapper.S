/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

        .section .rodata
.globl _TRaP_Linux_EntryPoint_init_dest
.hidden _TRaP_Linux_EntryPoint_init_dest
_TRaP_Linux_EntryPoint_init_dest:
    .long init_begin
.globl _TRaP_Linux_EntryPoint_entry_dest
.hidden _TRaP_Linux_EntryPoint_entry_dest
_TRaP_Linux_EntryPoint_entry_dest:
    .long entry_begin

.section .selfrando.entry, "ax", %progbits
.globl _TRaP_Linux_EntryPoint_init
.hidden _TRaP_Linux_EntryPoint_init
.type _TRaP_Linux_EntryPoint_init,%function
.arm
init_dest:
    .long init_begin
_TRaP_Linux_EntryPoint_init:
    // selfrando will patch this to the correct target
    // FIXME: use full 32-bit stub
    ldr r12, init_dest
    bx r12

init_begin:
    push {r1,lr}

    bl _TRaP_Linux_EntryPointImpl

    // Restore the finalizer pointer
    pop {r1,lr}

    // The library should have patched the entry point,
    // so go back and try again
    b _TRaP_Linux_EntryPoint_init

.globl _TRaP_Linux_EntryPoint_entry
.hidden _TRaP_Linux_EntryPoint_entry
.type _TRaP_Linux_EntryPoint_entry,%function
.arm
entry_dest:
    .long entry_begin
_TRaP_Linux_EntryPoint_entry:
    // selfrando will patch this to the correct target
    ldr r12, entry_dest
    bx r12

entry_begin:
    push {r1,lr}

    bl _TRaP_Linux_EntryPointImpl

    // Restore the finalizer pointer
    pop {r1,lr}

    // Go back and try again
    b _TRaP_Linux_EntryPoint_entry

.globl _TRaP_Linux_EntryPoint_return
.hidden _TRaP_Linux_EntryPoint_return
.type _TRaP_Linux_EntryPoint_return,%function
_TRaP_Linux_EntryPoint_return:
    bx lr

