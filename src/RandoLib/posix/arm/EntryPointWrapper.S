/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .selfrando.entry, "ax", %progbits
.globl selfrando_preinit
.hidden selfrando_preinit
.type selfrando_preinit, %function
.arm
// Relocation.cpp rewrites this to the real init function,
// and expects a PC-relative address (relative to itself)
preinit_pcrel:
    .long preinit_begin - selfrando_preinit

// The actual init entry point for our code
selfrando_preinit:
.cfi_startproc
    // selfrando will patch this to the correct target
    // FIXME: use full 32-bit stub
    ldr r12, preinit_pcrel
    add r12, r12, #selfrando_preinit - preinit_pcadd - 8
preinit_pcadd:
    add r12, r12, pc
    bx r12

preinit_begin:
    push {r0,lr}
.cfi_adjust_cfa_offset 8
.cfi_rel_offset r0, 0
.cfi_rel_offset lr, 4
    mov r0, #0
    bl selfrando_run
    pop {r0,lr}
.cfi_adjust_cfa_offset -8
.cfi_restore r0
.cfi_restore lr
    bx lr
.cfi_endproc
.size selfrando_preinit, . - selfrando_preinit


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
.cfi_startproc
    // selfrando will patch this to the correct target
    // FIXME: use full 32-bit stub
    ldr r12, init_pcrel
    add r12, r12, #selfrando_init - init_pcadd - 8
init_pcadd:
    add r12, r12, pc
    bx r12

init_begin:
    push {lr}
.cfi_adjust_cfa_offset 4
.cfi_rel_offset lr, 0
    bl selfrando_run_and_remove
    pop {lr}
.cfi_adjust_cfa_offset -4
.cfi_restore lr

    // The library should have patched the entry point,
    // so go back and try again
    b selfrando_init
.cfi_endproc
.size selfrando_init, . - selfrando_init


.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,%function
.arm
// See init_pcrel above
entry_pcrel:
    .long entry_begin - selfrando_entry

selfrando_entry:
.cfi_startproc
    ldr r12, entry_pcrel
    add r12, r12, #selfrando_entry - entry_pcadd - 8
entry_pcadd:
    add r12, r12, pc
    bx r12

entry_begin:
    push {r0,r1,lr}
.cfi_adjust_cfa_offset 12
.cfi_rel_offset r0, 0
.cfi_rel_offset r1, 4
.cfi_rel_offset lr, 8

    add r0, sp, #12
    bl selfrando_run
    // FIXME: we can't use selfrando_run_and_remove for now

    // Restore the finalizer pointer
    pop {r0,r1,lr}
.cfi_adjust_cfa_offset -12
.cfi_restore r0
.cfi_restore r1
.cfi_restore lr

    // Go back and try again
    b selfrando_entry
.cfi_endproc
.size selfrando_entry, . - selfrando_entry


.globl  selfrando_run_and_remove, selfrando_remove_call
.hidden selfrando_run_and_remove, selfrando_remove_call
.type   selfrando_run_and_remove,%function
.arm
selfrando_run_and_remove:
.cfi_startproc
    push {r0,lr}
.cfi_adjust_cfa_offset 8
.cfi_rel_offset r0, 0
.cfi_rel_offset lr, 4
    mov r0, #0
    bl selfrando_run
    // Fall-through
selfrando_remove_call:
    // TODO: add sequence that calls mprotect()
    pop {r0,lr}
.cfi_adjust_cfa_offset -8
.cfi_restore r0
.cfi_restore lr
    bx lr
.cfi_endproc
.size selfrando_run_and_remove, . - selfrando_run_and_remove


.globl selfrando_return
.hidden selfrando_return
.type selfrando_return,%function
selfrando_return:
.cfi_startproc
    bx lr
.cfi_endproc
.size selfrando_return, . - selfrando_return
