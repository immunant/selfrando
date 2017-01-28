/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

extern void _TRaP_Linux_EntryPointImpl(void) __attribute__((section(".selfrando.entry")));

// Make sure that we randomize as early as possible,
// by creating a .preinit_array entry for our entry point.
void (*const _TRaP_Linux_preinit_array[])(void)
    __attribute__((section(".preinit_array"), aligned(sizeof(void*)))) =
{
    &_TRaP_Linux_EntryPointImpl
};

