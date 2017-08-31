/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

        .section .rodata
.globl selfrando_init_dest
.hidden selfrando_init_dest
selfrando_init_dest:
    .long init_begin
.globl selfrando_entry_dest
.hidden selfrando_entry_dest
selfrando_entry_dest:
    .long entry_begin

.section .selfrando.entry, "ax", %progbits
.globl selfrando_init
.hidden selfrando_init
.type selfrando_init,%function
.arm
init_dest:
    .long init_begin
selfrando_init:
    // selfrando will patch this to the correct target
    // FIXME: use full 32-bit stub
    ldr r12, init_dest
    bx r12

init_begin:
    push {r1,lr}

    bl selfrando_run

    // Restore the finalizer pointer
    pop {r1,lr}

    // The library should have patched the entry point,
    // so go back and try again
    b selfrando_init

.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,%function
.arm
entry_dest:
    .long entry_begin
selfrando_entry:
    // selfrando will patch this to the correct target
    ldr r12, entry_dest
    bx r12

entry_begin:
    push {r1,lr}

    bl selfrando_run

    // Restore the finalizer pointer
    pop {r1,lr}

    // Go back and try again
    b selfrando_entry

.globl selfrando_return
.hidden selfrando_return
.type selfrando_return,%function
selfrando_return:
    bx lr

