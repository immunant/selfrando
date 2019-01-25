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

.section .preinit_array, "aw"
.p2align 2
.int selfrando_preinit
