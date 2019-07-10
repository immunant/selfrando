/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
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
    selfrando_preinit,
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
    trap_end_page __attribute__((weak)); // FIXME: this might not be available under -Bsymbolic

extern uintptr_t _GLOBAL_OFFSET_TABLE_[];
uintptr_t _DYNAMIC[] __attribute__((weak)) = {};
#pragma GCC visibility pop

void selfrando_run(uintptr_t *args) __attribute__((section(".selfrando.entry")));

void selfrando_run(uintptr_t *args) {
    struct ModuleInfo mod = { };
    mod.args = args;
    mod.orig_dt_init = (uintptr_t)(&orig_init);
    mod.orig_entry = (uintptr_t)(&orig_entry);
    mod.selfrando_preinit = (uintptr_t)(&selfrando_preinit);
    mod.selfrando_init = (uintptr_t)(&selfrando_init);
    mod.selfrando_entry = (uintptr_t)(&selfrando_entry);
    mod.selfrando_remove_call = (uintptr_t)(&selfrando_remove_call);
    mod.selfrando_return = (uintptr_t)(&selfrando_return);
    mod.xptramp_start = (uintptr_t)(&xptramp_begin);
    mod.xptramp_size = &xptramp_end - &xptramp_begin;
    mod.got_start = _GLOBAL_OFFSET_TABLE_;
    mod.dynamic = _DYNAMIC;
    if (&trap_end_page > &trap_end) {
        mod.trap_end_page = (uintptr_t)(&trap_end_page);
    }
    mod.num_sections = 1;
    mod.sections[0].start = (uintptr_t)(&text_begin);
    mod.sections[0].size = &text_end - &text_begin;
    mod.sections[0].trap = (uintptr_t)(&trap_begin);
    mod.sections[0].trap_size = &trap_end - &trap_begin;
    RandoMain(&mod);
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
