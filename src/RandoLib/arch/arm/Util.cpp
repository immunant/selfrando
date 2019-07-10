/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */


#include <OS.h>

bool os::APIImpl::is_one_byte_nop(os::BytePointer at) {
    return false;
}

void os::APIImpl::insert_nops(os::BytePointer at, size_t count) {
    for (size_t i = 0; i < count; ++i)
        at[i] = 0x0;
}

