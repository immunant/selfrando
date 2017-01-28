/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <asm/unistd.h>

.section .selfrando.entry, "ax", @progbits
.globl _TRaP_Linux_EntryPoint_init
.hidden _TRaP_Linux_EntryPoint_init
.type _TRaP_Linux_EntryPoint_init,@function
_TRaP_Linux_EntryPoint_init:
        // selfrando will patch this to the correct target
        .byte 0xe9
        .long 0x00000000

        push %rdx
        sub $8, %rsp // need to align stack to 16 bytes

        call _TRaP_Linux_EntryPointImpl

        add $8, %rsp
        pop %rdx

        // Try again
        jmp _TRaP_Linux_EntryPoint_init

.globl _TRaP_Linux_EntryPoint_entry
.hidden _TRaP_Linux_EntryPoint_entry
.type _TRaP_Linux_EntryPoint_entry,@function
_TRaP_Linux_EntryPoint_entry:
        .byte 0xe9
        .long 0x00000000

        push %rdx
        sub $8, %rsp // need to align stack to 16 bytes

        call _TRaP_Linux_EntryPointImpl

        add $8, %rsp
        pop %rdx

        // Try again
        jmp _TRaP_Linux_EntryPoint_entry

.globl _TRaP_Linux_EntryPoint_return
.hidden _TRaP_Linux_EntryPoint_return
.type _TRaP_Linux_EntryPoint_return,@function
_TRaP_Linux_EntryPoint_return:
        ret

.globl _TRaP_Linux_EntryPoint_mprotect
.hidden _TRaP_Linux_EntryPoint_mprotect
.type _TRaP_Linux_EntryPoint_mprotect,@function
_TRaP_Linux_EntryPoint_mprotect:
        movl $__NR_mprotect, %eax
        syscall
        ret

