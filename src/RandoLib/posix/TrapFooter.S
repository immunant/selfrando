/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "TrapCommon.h"

DEFINE_SECTION_SYMBOL(_TRaP_trap_end,    .txtrp,    "a",  %progbits)
DEFINE_SECTION_SYMBOL(_TRaP_xptramp_end, .textramp, "ax", %progbits)
DEFINE_SECTION_SYMBOL(_TRaP_got_end,     .got,      "wa", %progbits)
DEFINE_SECTION_SYMBOL(_TRaP_got_plt_end, .got.plt,  "wa", %progbits)
// FIXME: we may need separate section symbols for .igot and .igot.plt
