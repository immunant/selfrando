/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

// selfrando_init implementation
.section .selfrando.entry, "ax", @progbits
.globl selfrando_init
.hidden selfrando_init
.type selfrando_init,@function
selfrando_init:
.cfi_startproc
        // selfrando will patch this to the correct target
.byte 0xE9, 0x00, 0x00, 0x00, 0x00

        // Save the argument registers
        push %rdi // argc
.cfi_adjust_cfa_offset 8
.cfi_rel_offset %rdi, 0
        push %rsi // argv
.cfi_adjust_cfa_offset 8
.cfi_rel_offset %rsi, 0
        push %rdx // envp
.cfi_adjust_cfa_offset 8
.cfi_rel_offset %rdx, 0
        xor %rdi, %rdi
        call selfrando_run_and_remove
        pop %rdx
.cfi_restore %rdx
        pop %rsi
.cfi_restore %rsi
        pop %rdi
.cfi_restore %rdi
        jmp selfrando_init
.cfi_endproc
.size selfrando_init, . - selfrando_init


// selfrando_init implementation
.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,@function
selfrando_entry:
.cfi_startproc
        // selfrando will patch this to the correct target
.byte 0xE9, 0x00, 0x00, 0x00, 0x00

        // We're at the entry point, which means we have
        // the arguments, environment and auxv at the top
        // of the stack
        push %rdi
.cfi_adjust_cfa_offset 8
.cfi_rel_offset %rdi, 0
        push %rdx
.cfi_adjust_cfa_offset 8
.cfi_rel_offset %rdx, 0

        lea 24(%rsp), %rdi
        call selfrando_run_and_remove
        pop %rdx
.cfi_restore %rdx
        pop %rdi
.cfi_restore %rdi
        jmp selfrando_entry
.cfi_endproc
.size selfrando_entry, . - selfrando_entry


// selfrando_run_and_remove implementation
.globl selfrando_run_and_remove
.hidden selfrando_run_and_remove
.type selfrando_run_and_remove,@function
selfrando_run_and_remove:
.cfi_startproc
        push %rbp
.cfi_def_cfa_offset 16
.cfi_offset %rbp, -16
        mov %rsp, %rbp
.cfi_def_cfa_register %rbp

        and $-0x10, %rsp // need to align stack to 16 bytes
        call selfrando_run

.globl selfrando_remove_call
.hidden selfrando_remove_call
.type selfrando_remove_call, @object
selfrando_remove_call:
        // selfrando will patch this to a jump to
        // the munmap code, if we have it
.byte 0x0F, 0x1F, 0x44, 0x00, 0x00

        pop %rbp
.cfi_def_cfa %rsp, 8
        ret
.cfi_endproc
.size selfrando_run_and_remove, . - selfrando_run_and_remove


// selfrando_return implementation
.globl selfrando_return
.hidden selfrando_return
.type selfrando_return,@function
selfrando_return:
.cfi_startproc
        ret
.cfi_endproc
.size selfrando_return, . - selfrando_return
