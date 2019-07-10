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
selfrando_preinit:
.cfi_startproc
    // selfrando will patch this to selfrando_return
    .long 0x14000001
    stp x0, x30, [sp, #-16]!
.cfi_adjust_cfa_offset 16
.cfi_rel_offset x0, 0
.cfi_rel_offset x30, 8

    mov x0, #0
    bl selfrando_run_and_remove

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16
.cfi_adjust_cfa_offset -16
.cfi_restore x0
.cfi_restore x30
    ret
.cfi_endproc
.size selfrando_preinit, . - selfrando_preinit


.globl  selfrando_init
.hidden selfrando_init
.type   selfrando_init,%function
selfrando_init:
.cfi_startproc
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!
.cfi_adjust_cfa_offset 16
.cfi_rel_offset x0, 0
.cfi_rel_offset x30, 8

    mov x0, #0
    bl selfrando_run_and_remove

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16
.cfi_adjust_cfa_offset -16
.cfi_restore x0
.cfi_restore x30

    b selfrando_init
.cfi_endproc
.size selfrando_init, . - selfrando_init


.globl  selfrando_entry
.hidden selfrando_entry
.type   selfrando_entry,%function
selfrando_entry:
.cfi_startproc
    // selfrando will patch this to the correct target
    .long 0x14000001

    stp x0, x30, [sp, #-16]!
.cfi_adjust_cfa_offset 16
.cfi_rel_offset x0, 0
.cfi_rel_offset x30, 8

    add x0, sp, #16
    bl selfrando_run_and_remove

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16
.cfi_adjust_cfa_offset -16
.cfi_restore x0
.cfi_restore x30

    b selfrando_entry
.cfi_endproc
.size selfrando_entry, . - selfrando_entry


.globl  selfrando_run_and_remove, selfrando_remove_call
.hidden selfrando_run_and_remove, selfrando_remove_call
.type   selfrando_run_and_remove,%function
selfrando_run_and_remove:
.cfi_startproc
    stp x0, x30, [sp, #-16]!
.cfi_adjust_cfa_offset 16
.cfi_rel_offset x0, 0
.cfi_rel_offset x30, 8

    bl selfrando_run
    // Fall-through
selfrando_remove_call:
    // TODO: add sequence that calls mprotect()

    ldp x0, x30, [sp], #16
.cfi_adjust_cfa_offset -16
.cfi_restore x0
.cfi_restore x30

    ret
.cfi_endproc
.size selfrando_run_and_remove, . - selfrando_run_and_remove


.globl  selfrando_return
.hidden selfrando_return
.type   selfrando_return,%function
selfrando_return:
.cfi_startproc
    ret
.cfi_endproc
.size selfrando_return, . - selfrando_return
