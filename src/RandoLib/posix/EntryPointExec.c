/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

extern void Linux_EntryPointImpl(void) __attribute__((section(".selfrando.entry")));

extern void Linux_delete_layout_file(void);

// Make sure that we randomize as early as possible,
// by creating a .preinit_array entry for our entry point.
void (*const Linux_preinit_array[])(void)
    __attribute__((section(".preinit_array"), aligned(sizeof(void*)))) =
{
    &Linux_EntryPointImpl
};

void (*const Linux_fini_array[])(void)
    __attribute__((section(".fini_array"), aligned(sizeof(void*)))) =
{
#if RANDOLIB_WRITE_LAYOUTS > 0 && RANDOLIB_DELETE_LAYOUTS > 0
    &Linux_delete_layout_file,
#endif
};
