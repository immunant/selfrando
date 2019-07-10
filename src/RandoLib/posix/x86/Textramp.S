/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

.section .textramp, "ax", %progbits
.globl textramp_anchor
.hidden textramp_anchor
.type textramp_anchor, %object
textramp_anchor:
1:
    jmp 1b

