/*
 * This file is part of selfrando.
 * Copyright (c) 2018 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <bfdebug.h>

__attribute__((visibility("hidden")))
void _TRaP_bfdebug(const char *s) {
    BFDEBUG("%s", s);
}
