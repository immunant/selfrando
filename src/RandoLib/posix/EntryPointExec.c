/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

extern void selfrando_delete_layout_file(void);

void (*const selfrando_fini_array[])(void)
    __attribute__((section(".fini_array"), aligned(sizeof(void*)))) =
{
#if RANDOLIB_WRITE_LAYOUTS > 0 && RANDOLIB_DELETE_LAYOUTS > 0
    &selfrando_delete_layout_file,
#endif
};
