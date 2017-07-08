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

void RandoMain(struct ModuleInfo* asm_module);

extern char
    orig_init __attribute__((weak)),
    orig_entry __attribute__((weak));

#pragma GCC visibility push(hidden)
extern char
    Linux_EntryPoint_init,
    Linux_EntryPoint_entry,
    Linux_EntryPoint_return,
    xptramp_begin __attribute__((weak)),
    xptramp_end __attribute__((weak)),
    text_begin,
    text_end,
    trap_begin,
    trap_end,
    trap_end_page __attribute__((weak)), // FIXME: this might not be available under -Bsymbolic
    got_begin,
    got_plt_begin;

extern char _DYNAMIC __attribute__((weak));
#pragma GCC visibility pop

extern void Linux_EntryPoint_mprotect(void*, size_t, int) __attribute__((section(".selfrando.entry")));

void Linux_EntryPointImpl(void) __attribute__((section(".selfrando.entry")));

void Linux_EntryPointImpl(void) {
    struct TrapProgramInfoTable PIT;
    PIT.orig_dt_init = (uintptr_t)(&orig_init);
    PIT.orig_entry = (uintptr_t)(&orig_entry);
    PIT.rando_init = (uintptr_t)(&Linux_EntryPoint_init);
    PIT.rando_entry = (uintptr_t)(&Linux_EntryPoint_entry);
    PIT.rando_return = (uintptr_t)(&Linux_EntryPoint_return);
    PIT.xptramp_start = (uintptr_t)(&xptramp_begin);
    PIT.xptramp_size = &xptramp_end - &xptramp_begin;
    PIT.got_start = (uintptr_t*)(&got_begin);
    PIT.got_plt_start = (uintptr_t*)(&got_plt_begin);
    PIT.num_sections = 1;
    PIT.sections[0].start = (uintptr_t)(&text_begin);
    PIT.sections[0].size = &text_end - &text_begin;
    PIT.sections[0].trap = (uintptr_t)(&trap_begin);
    PIT.sections[0].trap_size = &trap_end - &trap_begin;
    PIT.sections[1].start = 0;
    PIT.sections[1].size = 0;
    // FIXME: we use sections[1] to store the span of the full page-aligned
    // section, so we can pass the limits later to mprotect()
    PIT.sections[1].trap = (uintptr_t)(&trap_begin);
    PIT.sections[1].trap_size = &trap_end_page - &trap_begin;

    struct ModuleInfo module_info;
    module_info.dynamic = (BytePointer)&_DYNAMIC;
    module_info.program_info_table = &PIT;

    RandoMain(&module_info);

#if RANDOLIB_IS_X86_64 // FIXME: other architectures too
    // Prevent access to selfrando code and constants
    if (&trap_end_page != NULL) {
        Linux_EntryPoint_mprotect((void*)PIT.sections[1].trap,
                                        PIT.sections[1].trap_size,
                                        PROT_NONE);
    }
#endif
}

// Add a declaration for dl_phdr_info
struct dl_phdr_info;

// Add this as a forced reference to dl_iterate_phdr, so we can link to it
int
__attribute__((section(".selfrando.entry"),
               visibility("hidden")))
x_dl_iterate_phdr(int (*callback) (struct dl_phdr_info *info,
                                   size_t size, void *data),
                  void *data) {
    extern int dl_iterate_phdr(int (*callback) (struct dl_phdr_info *info,
                                                size_t size, void *data),
                               void *data);
    return dl_iterate_phdr(callback, data);
}
