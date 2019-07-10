/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

void _randolib_init() {
    // Android doesn't have a DT_INIT for shared libraries, but we need
    // something to patch with PatchEntry. This just adds a dummy function that
    // will be picked up by the linker as the DT_INIT entry point.
}
