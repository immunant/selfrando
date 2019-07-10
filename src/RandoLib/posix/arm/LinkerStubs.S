/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */


# File that marks the beginning of the linker stubs
# For this to work, this file needs to be the very last file
# on the linker command line

.text

.globl LinkerStubs
.type LinkerStubs, %function

LinkerStubs:
    nop

