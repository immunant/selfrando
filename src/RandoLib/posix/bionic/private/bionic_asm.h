/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PRIVATE_BIONIC_ASM_H_
#define _PRIVATE_BIONIC_ASM_H_

#include <asm/unistd.h> /* For system call numbers. */
#include <asm/errno.h>
#define MAX_ERRNO 4095  /* For recognizing system call error returns. */

#define __bionic_asm_custom_entry(f)
#define __bionic_asm_custom_end(f)
#define __bionic_asm_function_type @function

#include <machine/asm.h>

#ifdef NOUNWIND
#define __unwind .cantunwind
#else
#define __unwind
#endif

#define ENTRY(f) \
    .text; \
    .globl _TRaP_libc_##f; \
    .hidden _TRaP_libc_##f; \
    .align __bionic_asm_align; \
    .type _TRaP_libc_##f, __bionic_asm_function_type; \
    _TRaP_libc_##f: \
    __bionic_asm_custom_entry(_TRaP_libc_##f); \
    .cfi_startproc;                            \
    __unwind                                   \

#define ENTRY_SYSCALL(f) \
    .text; \
    .globl _TRaP_syscall_##f; \
    .hidden _TRaP_syscall_##f; \
    .align __bionic_asm_align; \
    .type _TRaP_syscall_##f, __bionic_asm_function_type; \
    _TRaP_syscall_##f: \
    __bionic_asm_custom_entry(_TRaP_syscall_##f); \
    .cfi_startproc;                               \
    __unwind                                      \

#define END(f) \
    .cfi_endproc; \
    .size _TRaP_libc_##f, .-_TRaP_libc_##f; \
    __bionic_asm_custom_end(_TRaP_libc_##f) \

#define END_SYSCALL(f) \
    .cfi_endproc; \
    .size _TRaP_syscall_##f, .-_TRaP_syscall_##f; \
    __bionic_asm_custom_end(_TRaP_syscall_##f) \

#define ALIAS_SYMBOL(alias, original) \
    .globl _TRaP_libc_##alias; \
    .hidden _TRaP_libc_##alias; \
    .equ _TRaP_libc_##alias, _TRaP_libc_##original

#define ALIAS_SYMBOL_SYSCALL(alias, original) \
    .globl _TRaP_syscall_##alias; \
    .hidden _TRaP_syscall_##alias; \
    .equ _TRaP_syscall_##alias, _TRaP_syscall_##original

#endif /* _PRIVATE_BIONIC_ASM_H_ */
