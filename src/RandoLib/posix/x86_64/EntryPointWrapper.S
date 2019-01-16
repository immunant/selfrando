/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .selfrando.entry, "ax", @progbits
.globl selfrando_init
.hidden selfrando_init
.type selfrando_init,@function
selfrando_init:
1:
        // selfrando will patch this to the correct target
        call selfrando_run_and_remove
        jmp 1b

.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,@function
selfrando_entry:
1:
        // selfrando will patch this to the correct target
        call 2f
        jmp 1b

2:
        // We're at the entry point, which means we have
        // the arguments, environment and auxv at the top
        // of the stack
        push %rdi
        lea 16(%rsp), %rdi
        jmp srr_have_args

.globl selfrando_run_and_remove
.hidden selfrando_run_and_remove
.type selfrando_run_and_remove,@function
selfrando_run_and_remove:
        push %rdi
        xor %rdi, %rdi

srr_have_args:
        push %rdx
        push %rbp
        mov %rsp, %rbp
        and $-0x10, %rsp // need to align stack to 16 bytes

        call selfrando_run

.globl selfrando_remove_call
.hidden selfrando_remove_call
selfrando_remove_call:
        // selfrando will patch this to a jump to
        // the munmap code, if we have it
.byte 0x0F, 0x1F, 0x44, 0x00, 0x00

        mov %rbp, %rsp
        pop %rbp
        pop %rdx
        pop %rdi
        ret

.globl selfrando_return
.hidden selfrando_return
.type selfrando_return,@function
selfrando_return:
        ret
