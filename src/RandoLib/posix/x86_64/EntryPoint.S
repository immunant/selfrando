/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <asm/unistd.h>
#include <asm/mman.h>

// WARNING!!! This must be kept in sync with ProgramTableInfo
.set PIT_DT_INIT_OFFSET, 0
.set PIT_ENTRY_OFFSET, 8

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
    .fill 13, 8, 0

// We put our trampolines in .init because we don't
// bother randomizing them for now (too small)
.section .init, "ax", @progbits
// The linker concatenates all .init sections
// and considers them linear (each one continues
// execution into the next), so we need to jump
// over our own code
_TRaP_SkipInit:
    jmp _TRaP_InitEnd

#define COMPUTE_ADDRESS(symbol, dest_reg) \
    lea symbol(%rip), dest_reg

#define SELF_UNMAP \
    push %rax; \
    mov $__NR_mprotect, %rax; /* syscall number */ \
    COMPUTE_ADDRESS(_TRaP_Linux_Begin, %rdi); /* unsigned long addr */ \
    COMPUTE_ADDRESS(_TRaP_Linux_End, %rsi); sub %rdi, %rsi; /* size_t len */ \
    mov $PROT_NONE, %rdx; /* unsigned long prot */ \
    syscall; \
    testl %eax, %eax; \
    jnz abort@plt; /* abort if syscall fails */ \
    pop %rax; \
    
// FIXME: RandoLib stores the new program entry point
// inside its own new_program_entry, which might be a
// problem when randomizing shared libraries

.globl _TRaP_Linux_EntryTrampoline
.type _TRaP_Linux_EntryTrampoline,@function
_TRaP_Linux_EntryTrampoline:
    // Initialize RandoLib (if it hasn't been already)
    push %rdx      // Preserve the finalizer function pointer

    // push ProgramInfoTable
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %rdx)
    push %rdx
    // push _DYNAMIC
    COMPUTE_ADDRESS(_DYNAMIC, %rdx)
    push %rdx
    // RandoMain parameter: the pointer to this structure
    mov %rsp, %rdi

    call _TRaP_RandoMain
    add $16, %rsp   // Pop structure
    
    SELF_UNMAP

    // Restore the finalizer pointer
    pop %rdx

    // Jump to new entry point
    // FIXME: is this always in .init???
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %rax)
    mov PIT_ENTRY_OFFSET(%rax), %rax

#ifndef SR_NEEDS_ENTRY_POINT_TEST
    jmp *%rax

#else //SR_NEEDS_ENTRY_POINT_TEST
    test %rax, %rax
    jz 1f
    jmp *%rax
1:
    ret
#endif

.globl _TRaP_Linux_InitTrampoline
.type _TRaP_Linux_InitTrampoline,@function
_TRaP_Linux_InitTrampoline:
    // Initialize RandoLib (if it hasn't been already)
    push %rdi
    // push ProgramInfoTable
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %rdi)
    push %rdi
    // push _DYNAMIC
    COMPUTE_ADDRESS(_DYNAMIC, %rdi)
    push %rdi
    mov %rsp, %rdi

    call _TRaP_RandoMain
    add $16, %rsp   // Pop asm_handle

    SELF_UNMAP

    pop %rdi

    // Jump to the new init function
    // FIXME: is this always in .init???
    COMPUTE_ADDRESS(_local_ProgramInfoTable, %rax)
    mov PIT_DT_INIT_OFFSET(%rax), %rax

#ifndef SR_NEEDS_ENTRY_POINT_TEST
    jmp *%rax

#else //SR_NEEDS_ENTRY_POINT_TEST
    test %rax, %rax
    jz 1f
    jmp *%rax
1:
    ret
#endif

_TRaP_InitEnd:
    nop


