/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "TrapCommon.h"

DEFINE_SECTION_SYMBOL(trap_end,    .txtrp,    "a",  %progbits)
DEFINE_SECTION_SYMBOL(xptramp_end, .textramp, "ax", %progbits)
