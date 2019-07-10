/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "TrapCommon.h"

DEFINE_SECTION_SYMBOL(_TRaP_trap_end,    .txtrp,    "a",  %progbits)
DEFINE_SECTION_SYMBOL(_TRaP_xptramp_end, .textramp, "ax", %progbits)
