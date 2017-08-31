/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#ifndef __RANDOLIB_MODULEINFO_H
#define __RANDOLIB_MODULEINFO_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t *BytePointer;

// FIXME: move this to a header shared with PatchEntry
enum {
    TRAP_SECTION_TEXT = 0,
    TRAP_SECTION_PLT,
    // Total number of sections
    TRAP_NUM_SECTIONS
};

struct TrapSectionInfoTable {
    uintptr_t start, trap;
    size_t size, trap_size;
};

// ELF-specific information that PatchEntry fills in
struct TrapProgramInfoTable {
    uintptr_t orig_dt_init;
    uintptr_t orig_entry;

    // Locations of entry trampolines to relocate
    uintptr_t selfrando_init;
    uintptr_t selfrando_entry;
    uintptr_t selfrando_return;

    // Location of export trampoline table
    uintptr_t xptramp_start;
    size_t xptramp_size;

    // Location of GOT
    uintptr_t *got_start;
    uintptr_t *got_plt_start;

    // Location of linker stubs
    uintptr_t linker_stubs;

    // Location of .text section
    // FIXME: for now, assume that there is only a fixed
    // number of sections and they contain all the code
    // Custom linker scripts may break this
    // We still put in a num_sections field, for future use
    // Also, we use num_sections to mark whether
    // we've added the sections to the table or not
    size_t num_sections;
    struct TrapSectionInfoTable sections[TRAP_NUM_SECTIONS];
};

struct ModuleInfo {
    BytePointer dynamic;
    struct TrapProgramInfoTable *program_info_table;
};

#endif
