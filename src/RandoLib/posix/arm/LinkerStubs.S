/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */


# File that marks the beginning of the linker stubs
# For this to work, this file needs to be the very last file
# on the linker command line

.text

.globl _TRaP_LinkerStubs
.type _TRaP_LinkerStubs, %function

_TRaP_LinkerStubs:
    nop

