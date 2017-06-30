/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <asm/unistd.h>

.section .selfrando.entry, "ax", @progbits
.globl Linux_EntryPoint_init
.hidden Linux_EntryPoint_init
.type Linux_EntryPoint_init,@function
Linux_EntryPoint_init:
        // selfrando will patch this to the correct target
        .byte 0xe9
        .long 0x00000000

        push %edx
        call Linux_EntryPointImpl
        pop %edx

        // Try again
        jmp Linux_EntryPoint_init

.globl Linux_EntryPoint_entry
.hidden Linux_EntryPoint_entry
.type Linux_EntryPoint_entry,@function
Linux_EntryPoint_entry:
        .byte 0xe9
        .long 0x00000000

        push %edx
        call Linux_EntryPointImpl
        pop %edx

        // Try again
        jmp Linux_EntryPoint_entry

.globl Linux_EntryPoint_return
.hidden Linux_EntryPoint_return
.type Linux_EntryPoint_return,@function
Linux_EntryPoint_return:
        ret

.globl Linux_EntryPoint_mprotect
.hidden Linux_EntryPoint_mprotect
.type Linux_EntryPoint_mprotect,@function
Linux_EntryPoint_mprotect:
        movl $__NR_mprotect, %eax
        // TODO: copy arguments to ebx/ecx/edx
        int $0x80
        ret

// On 32-bit x86, some versions of crti.o from glibc
// include a version of __x86_get_pc_thunk.bx using
// a linkonce section, which we cannot attack a .txtrp to
// Instead, we manually add the same function here in a
// single-element group section, and also include the
// corresponding trap info
.section .text.__x86.get_pc_thunk.bx, "axG", @progbits, Linux_EntryPoint__x86.get_pc_thunk.bx,comdat
.globl	Linux_EntryPoint__x86.get_pc_thunk.bx
.hidden	Linux_EntryPoint__x86.get_pc_thunk.bx
.align 4
.type	Linux_EntryPoint__x86.get_pc_thunk.bx,@function
Linux_EntryPoint__x86.get_pc_thunk.bx:
        movl	(%esp), %ebx
        ret


// The .txtrp section for the thunk above
.section .txtrp, "a", @progbits
.local	Linux_EntryPoint__x86.get_pc_thunk.bx.txtrp
Linux_EntryPoint__x86.get_pc_thunk.bx.txtrp:
1:
// FirstSymAddr
.int 0
.reloc 1b, R_386_GOTOFF, Linux_EntryPoint__x86.get_pc_thunk.bx

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
.reloc 1b, R_386_NONE, Linux_EntryPoint__x86.get_pc_thunk.bx.txtrp
