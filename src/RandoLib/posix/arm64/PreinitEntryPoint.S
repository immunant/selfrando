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
.type selfrando_preinit,@function
selfrando_preinit:
1:
    // selfrando will patch this to selfrando_return
    .long 0x14000001
    stp x0, x30, [sp, #-16]!

    mov x0, #0
    bl selfrando_run

    // Restore the finalizer pointer and link register
    ldp x0, x30, [sp], #16
    ret

.section .preinit_array, "aw"
.p2align 3
.quad selfrando_preinit
