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
        push %edx
        call selfrando_run
        pop %edx
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
        push %ebx
        push %ecx
        push %edx
        movl $__NR_mprotect, %eax
        mov 16(%esp), %ebx
        mov 20(%esp), %ecx
        mov 24(%esp), %edx
        int $0x80
        pop %edx
        pop %ecx
        pop %ebx
        ret

// On 32-bit x86, some versions of crti.o from glibc
// include a version of __x86_get_pc_thunk.bx using
// a linkonce section, which we cannot attack a .txtrp to
// Instead, we manually add the same function here in a
// single-element group section, and also include the
// corresponding trap info
.section .text.selfrando__x86.get_pc_thunk.bx, "axG", @progbits, selfrando__x86.get_pc_thunk.bx,comdat
.globl	selfrando__x86.get_pc_thunk.bx
.hidden	selfrando__x86.get_pc_thunk.bx
.align 4
.type	selfrando__x86.get_pc_thunk.bx,@function
selfrando__x86.get_pc_thunk.bx:
        movl	(%esp), %ebx
        ret


// The .txtrp section for the thunk above
.section .txtrp, "a", @progbits
.local	selfrando__x86.get_pc_thunk.bx.txtrp
selfrando__x86.get_pc_thunk.bx.txtrp:
1:
// FirstSymAddr
.int 0
.reloc 1b, R_386_GOTOFF, selfrando__x86.get_pc_thunk.bx

// FirstSymbol
.uleb128 00
.uleb128 02 // 4-byte alignment

// Symbols
.uleb128 00
.uleb128 00

// Relocs
.uleb128 00
.uleb128 00

// PaddingOffset
.uleb128 00
// PaddingSize
.uleb128 00


// Add a forced anchor in .init to make sure .txtrp gets included
.section .init, "ax", @progbits
1:
.byte 0x90
.reloc 1b, R_386_NONE, selfrando__x86.get_pc_thunk.bx.txtrp
