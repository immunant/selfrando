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
    selfrando_init,
    selfrando_entry,
    selfrando_return,
    selfrando_remove_call,
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
extern char _GLOBAL_OFFSET_TABLE_ __attribute__((weak));
#pragma GCC visibility pop

void selfrando_run(void) __attribute__((section(".selfrando.entry")));

void selfrando_run(void) {
    struct TrapProgramInfoTable PIT = { };
    PIT.orig_dt_init = (uintptr_t)(&orig_init);
    PIT.orig_entry = (uintptr_t)(&orig_entry);
    PIT.selfrando_init = (uintptr_t)(&selfrando_init);
    PIT.selfrando_entry = (uintptr_t)(&selfrando_entry);
    PIT.selfrando_remove_call = (uintptr_t)(&selfrando_remove_call);
    PIT.selfrando_return = (uintptr_t)(&selfrando_return);
    PIT.xptramp_start = (uintptr_t)(&xptramp_begin);
    PIT.xptramp_size = &xptramp_end - &xptramp_begin;
    PIT.got_start = (uintptr_t*)(&got_begin);
    if (&_GLOBAL_OFFSET_TABLE_ != NULL) {
        PIT.got_plt_start = (uintptr_t*)(&_GLOBAL_OFFSET_TABLE_);
    } else {
        PIT.got_plt_start = (uintptr_t*)(&got_plt_begin);
    }
    if (&trap_end_page > &trap_end) {
        PIT.trap_end_page = (uintptr_t)(&trap_end_page);
    }
    PIT.num_sections = 1;
    PIT.sections[0].start = (uintptr_t)(&text_begin);
    PIT.sections[0].size = &text_end - &text_begin;
    PIT.sections[0].trap = (uintptr_t)(&trap_begin);
    PIT.sections[0].trap_size = &trap_end - &trap_begin;

    struct ModuleInfo module_info;
    module_info.dynamic = (BytePointer)&_DYNAMIC;
    module_info.program_info_table = &PIT;
    RandoMain(&module_info);
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
