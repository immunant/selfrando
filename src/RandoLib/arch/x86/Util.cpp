/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */


#include <OS.h>

bool os::APIImpl::is_one_byte_nop(os::BytePointer at) {
    return at[0] == 0x90 || at[0] == 0xCC;
}

void os::APIImpl::insert_nops(os::BytePointer at, size_t count) {
    switch(count) {
    case 1:
        at[0] = 0x90;
        return;
    case 2:
        at[0] = 0x66;
        at[1] = 0x90;
        return;
    case 3:
        at[0] = 0x0F;
        at[1] = 0x1F;
        at[2] = 0x00;
        return;
    default:
        while (count-- > 0)
            *at++ = 0x90;
        return;
    }
}

