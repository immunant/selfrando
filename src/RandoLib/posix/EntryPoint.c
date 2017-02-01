/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

/* C implementation of the selfrando library entry point. Supersedes EntryPoint.S */

#include "ModuleInfo.h"

#include <sys/mman.h>

void _TRaP_RandoMain(struct ModuleInfo* asm_module);

extern char
    _TRaP_orig_init __attribute__((weak)),
    _TRaP_orig_entry __attribute__((weak));

#pragma GCC visibility push(hidden)
extern char
    _TRaP_Linux_EntryPoint_init,
    _TRaP_Linux_EntryPoint_entry,
    _TRaP_Linux_EntryPoint_return,
    _TRaP_xptramp_begin __attribute__((weak)),
    _TRaP_xptramp_end __attribute__((weak)),
    _TRaP_text_begin,
    _TRaP_text_end,
    _TRaP_trap_begin,
    _TRaP_trap_end,
    _TRaP_trap_end_page __attribute__((weak)), // FIXME: this might not be available under -Bsymbolic
    _TRaP_got_begin,
    _TRaP_got_end,
    _TRaP_got_plt_begin,
    _TRaP_got_plt_end,
    _TRaP_dynamic;
#pragma GCC visibility pop

extern void _TRaP_Linux_EntryPoint_mprotect(void*, size_t, int) __attribute__((section(".selfrando.entry")));

extern char __executable_start;
extern char __etext;

void _TRaP_Linux_EntryPointImpl(void) __attribute__((section(".selfrando.entry")));

void _TRaP_Linux_EntryPointImpl(void) {
    struct TrapProgramInfoTable PIT;
    PIT.orig_dt_init = (uintptr_t)(&_TRaP_orig_init);
    PIT.orig_entry = (uintptr_t)(&_TRaP_orig_entry);
    PIT.rando_init = (uintptr_t)(&_TRaP_Linux_EntryPoint_init);
    PIT.rando_entry = (uintptr_t)(&_TRaP_Linux_EntryPoint_entry);
    PIT.rando_return = (uintptr_t)(&_TRaP_Linux_EntryPoint_return);
    PIT.xptramp_start = (uintptr_t)(&_TRaP_xptramp_begin);
    PIT.xptramp_size = &_TRaP_xptramp_end - &_TRaP_xptramp_begin;
    PIT.got_start = (uintptr_t*)(&_TRaP_got_begin);
    PIT.got_end = (uintptr_t*)(&_TRaP_got_end);
    PIT.got_plt_start = (uintptr_t*)(&_TRaP_got_plt_begin);
    PIT.got_plt_end = (uintptr_t*)(&_TRaP_got_plt_end);
    PIT.num_sections = 1;
    PIT.sections[0].start = (uintptr_t)(&_TRaP_text_begin);
    PIT.sections[0].size = &_TRaP_text_end - &_TRaP_text_begin;
    PIT.sections[0].trap = (uintptr_t)(&_TRaP_trap_begin);
    PIT.sections[0].trap_size = &_TRaP_trap_end - &_TRaP_trap_begin;
    PIT.sections[1].start = 0;
    PIT.sections[1].size = 0;
    PIT.sections[1].trap = 0;
    PIT.sections[1].trap_size = 0;

    struct ModuleInfo module_info;
    module_info.dynamic = (BytePointer)&_TRaP_dynamic;
    module_info.program_info_table = &PIT;

    _TRaP_RandoMain(&module_info);

#if RANDOLIB_IS_X86_64 // FIXME: other architectures too
    // Prevent access to selfrando code and constants
    if (&_TRaP_trap_end_page != NULL) {
        size_t trap_page_size = &_TRaP_trap_end_page - &_TRaP_trap_begin;
        _TRaP_Linux_EntryPoint_mprotect((void*)&_TRaP_trap_begin,
                                        trap_page_size,
                                        PROT_NONE);
    }
#endif
}
