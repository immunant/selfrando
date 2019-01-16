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
.arm
// Relocation.cpp rewrites this to the real init function,
// and expects a PC-relative address (relative to itself)
init_pcrel:
    .long init_begin - selfrando_init

// The actual init entry point for our code
selfrando_init:
    // selfrando will patch this to the correct target
    // FIXME: use full 32-bit stub
    ldr r12, init_pcrel
    add r12, r12, #selfrando_init - init_pcadd - 8
init_pcadd:
    add r12, r12, pc
    bx r12

init_begin:
    push {lr}
    bl selfrando_run_and_remove
    pop {lr}

    // The library should have patched the entry point,
    // so go back and try again
    b selfrando_init

.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,%function
.arm
// See init_pcrel above
entry_pcrel:
    .long entry_begin - selfrando_entry

selfrando_entry:
    ldr r12, entry_pcrel
    add r12, r12, #selfrando_entry - entry_pcadd - 8
entry_pcadd:
    add r12, r12, pc
    bx r12

entry_begin:
    push {r0,r1,lr}

    add r0, sp, #12
    bl selfrando_run
    // FIXME: we can't use selfrando_run_and_remove for now

    // Restore the finalizer pointer
    pop {r0,r1,lr}

    // Go back and try again
    b selfrando_entry

.globl  selfrando_run_and_remove, selfrando_remove_call
.hidden selfrando_run_and_remove, selfrando_remove_call
.type   selfrando_run_and_remove,%function
.arm
selfrando_run_and_remove:
    push {r0,lr}
    mov r0, #0
    bl selfrando_run
    // Fall-through
selfrando_remove_call:
    // TODO: add sequence that calls mprotect()
    pop {r0,pc}

.globl selfrando_return
.hidden selfrando_return
.type selfrando_return,%function
selfrando_return:
    bx lr

