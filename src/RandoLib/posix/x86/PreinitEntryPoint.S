/*
 * This file is part of selfrando.
 * Copyright (c) 2019 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .selfrando.entry, "ax", @progbits
.globl selfrando_preinit
.hidden selfrando_preinit
.type selfrando_preinit,@function
selfrando_preinit:
        // selfrando will patch this to selfrando_return
        jmp selfrando_run_and_remove

.section .preinit_array, "aw"
.p2align 2
.int selfrando_preinit
