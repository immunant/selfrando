/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */


__attribute__((visibility("hidden")))
long __set_errno_internal(int i) {
    return -1;
}
