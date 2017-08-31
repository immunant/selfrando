/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <asm/unistd.h>

.section .selfrando.entry, "ax", @progbits
.globl selfrando_init
.hidden selfrando_init
.type selfrando_init,@function
selfrando_init:
1:
        // selfrando will patch this to the correct target
        call .Lcall_selfrando
        jmp 1b

.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,@function
selfrando_entry:
1:
        // selfrando will patch this to the correct target
        call .Lcall_selfrando
        jmp 1b

.Lcall_selfrando:
        push %rdx
        push %rbp
        mov %rsp, %rbp
        and $-0x10, %rsp // need to align stack to 16 bytes

        call selfrando_run

        mov %rbp, %rsp
        pop %rbp
        pop %rdx
        ret

.globl selfrando_return
.hidden selfrando_return
.type selfrando_return,@function
selfrando_return:
        ret

.globl selfrando_mprotect
.hidden selfrando_mprotect
.type selfrando_mprotect,@function
selfrando_mprotect:
        movl $__NR_mprotect, %eax
        syscall
        ret

