/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

// WARNING!!! This must be kept in sync with ProgramTableInfo
.set PIT_DT_INIT_OFFSET, 0
.set PIT_ENTRY_OFFSET, 4

.extern _TRaP_RandoMain@plt
.extern _GLOBAL_OFFSET_TABLE_
.extern _DYNAMIC

.data
// The ProgramInfoTable
// The linker will not automatically pull this in
// so we need to compile with -Wl,-u,_TRaP_ProgramInfoTable
// We need to export it so that PatchEntry can find it
.globl _TRaP_ProgramInfoTable
.type _TRaP_ProgramInfoTable, @object
_TRaP_ProgramInfoTable:
_local_ProgramInfoTable:
    .fill 13, 4, 0

// We put our trampolines in .init because we don't
// bother randomizing them for now (too small)
.section .init, "ax", @progbits
// The linker concatenates all .init sections
// and considers them linear (each one continues
// execution into the next), so we need to jump
// over our own code
_TRaP_SkipInit:
    jmp _TRaP_InitEnd

// We have 2 TODOs here:
// 1) Figure out a way to do this using a CALL/RET pair
//    instead of CALL/POP (faster, interacts well with RAS)
// 2) Figure out a way to reuse the PC value from one instantiation
//    to the next (for example, when pushing _TRaP_RandoMain arguments below)

#define COMPUTE_ADDRESS(symbol, dest_reg) \
    .byte 0xE8; .long 0; /* call next instruction, push its address */ \
    .set __CA_anchor, .; \
    pop dest_reg; \
    lea (symbol - __CA_anchor)(dest_reg), dest_reg;

// FIXME: RandoLib stores the new program entry point
// inside its own new_program_entry, which might be a
// problem when randomizing shared libraries

.globl _TRaP_Linux_EntryTrampoline
.type _TRaP_Linux_EntryTrampoline,@function
_TRaP_Linux_EntryTrampoline:
    // Initialize RandoLib (if it hasn't been already)
    push %edx      // Preserve the finalizer function pointer

    // push ProgramInfoTable
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %edx)
    push %edx
    // push _DYNAMIC
    COMPUTE_ADDRESS(_DYNAMIC, %edx)
    push %edx
    // Push pointer to this structure
    push %esp // Parameter: asm_handle

    COMPUTE_ADDRESS(_GLOBAL_OFFSET_TABLE_, %ebx)
    call _TRaP_RandoMain@plt
    add $12, %esp   // Pop asm_handle

    // Restore the finalizer pointer
    pop %edx

    // Jump to new entry point
    // FIXME: is this always in .init???
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %eax)
    mov PIT_ENTRY_OFFSET(%eax), %eax
    test %eax, %eax
    jz 1f
    jmp *%eax

1:
    ret

.globl _TRaP_Linux_InitTrampoline
.type _TRaP_Linux_InitTrampoline,@function
_TRaP_Linux_InitTrampoline:
    // Initialize RandoLib (if it hasn't been already)
    // push _DYNAMIC
    push %ecx
    // push _DYNAMIC
    COMPUTE_ADDRESS(_DYNAMIC, %ecx)
    push %ecx
    push %esp // Parameter: asm_handle
    // push ProgramInfoTable
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %ecx)
    xchg %ecx, 8(%esp)

    COMPUTE_ADDRESS(_GLOBAL_OFFSET_TABLE_, %ebx)
    call _TRaP_RandoMain@plt
    add $12, %esp   // Pop asm_handle
    // TODO: should we store %eax in PIT???

    // Jump to the new init function
    // FIXME: is this always in .init???
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %eax)
    mov PIT_DT_INIT_OFFSET(%eax), %eax
    test %eax, %eax
    jz 1f
    jmp *%eax

1:
    ret

_TRaP_InitEnd:
    nop


