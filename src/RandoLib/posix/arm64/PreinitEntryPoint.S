/*
 * This file is part of selfrando.
 * Copyright (c) 2019 Immunant Inc.
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
    bl selfrando_run

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16
.cfi_adjust_cfa_offset -16
.cfi_restore x0
.cfi_restore x30
    ret
.cfi_endproc
.size selfrando_preinit, . - selfrando_preinit

.section .preinit_array, "aw"
.p2align 3
.quad selfrando_preinit
