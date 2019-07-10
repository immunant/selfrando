/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .selfrando.entry, "ax", @progbits
// selfrando_preinit implementation
// See comments in x86_64/EntryPointWrapper.S
.globl selfrando_preinit
.hidden selfrando_preinit
.type selfrando_preinit,@function
selfrando_preinit:
.cfi_startproc
        // selfrando will patch this to selfrando_return
.byte 0xE9, 0x00, 0x00, 0x00, 0x00

        xor %edx, %edx
        call selfrando_run_and_remove
        jmp selfrando_preinit
.cfi_endproc
.size selfrando_preinit, . - selfrando_preinit


// selfrando_init implementation
.globl selfrando_init
.hidden selfrando_init
.type selfrando_init,@function
selfrando_init:
.cfi_startproc
        // selfrando will patch this to the correct target
.byte 0xE9, 0x00, 0x00, 0x00, 0x00

        xor %edx, %edx
        call selfrando_run_and_remove
        jmp selfrando_init
.cfi_endproc
.size selfrando_init, . - selfrando_init


// selfrando_entry implementation
.globl selfrando_entry
.hidden selfrando_entry
.type selfrando_entry,@function
selfrando_entry:
.cfi_startproc
        // selfrando will patch this to the correct target
.byte 0xE9, 0x00, 0x00, 0x00, 0x00

        push %edx
.cfi_adjust_cfa_offset 4
.cfi_rel_offset %edx, 0
        lea 4(%esp), %edx
        call selfrando_run_and_remove

        pop %edx
.cfi_adjust_cfa_offset -4
.cfi_restore %edx
        jmp selfrando_entry
.cfi_endproc
.size selfrando_entry, . - selfrando_entry


// selfrando_run_and_remove implementation
// Incoming arguments:
//   %edx == entry points arguments from kernel
//           or NULL for preinit/init
.globl selfrando_run_and_remove
.hidden selfrando_run_and_remove
.type selfrando_run_and_remove,@function
selfrando_run_and_remove:
.cfi_startproc
        push %edx
.cfi_adjust_cfa_offset 4
.cfi_rel_offset %edx, 0
        call selfrando_run
        add $4, %esp
.cfi_adjust_cfa_offset -4

.globl selfrando_remove_call
.hidden selfrando_remove_call
selfrando_remove_call:
        // selfrando will patch this to a jump to
        // the munmap code, if we have it
.byte 0x0F, 0x1F, 0x44, 0x00, 0x00
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
.reloc 1b, R_386_PC32, selfrando__x86.get_pc_thunk.bx

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
