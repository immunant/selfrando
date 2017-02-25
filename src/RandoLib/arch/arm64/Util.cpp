/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */


#include <OS.h>

bool os::APIImpl::Is1ByteNOP(os::BytePointer at) {
    return false;
}

void os::APIImpl::InsertNOPs(os::BytePointer at, size_t count) {
    for (size_t i = 0; i < count; ++i)
        at[i] = 0x0;
}

