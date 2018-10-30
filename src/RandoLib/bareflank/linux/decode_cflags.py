#!/usr/bin/python3
#
# This file is part of selfrando.
# Copyright (c) 2018 Immunant Inc.
# For license information, see the LICENSE file
# included with selfrando.


import json
import os
import sys

PREFIX_BLACKLIST = [
    # Ignore arguments for the linker or preprocessor
    "-Wl,",
    "-Wp,",
    # We're compiling C++, so ignore the C version
    "-std=",
    # Let CMake control the optimization level
    "-O",
]

ARGUMENT_BLACKLIST = {
    "-E",
    "-c",
    "-o",
    "-pipe",
    # We really need some system headers, like `stdint.h` and `utility`
    "-nostdinc",
    # Not applicable to C++
    "-Wstrict-prototypes",
    "-Wdeclaration-after-statement",
    "-Wno-pointer-sign",
    # Selfrando relies on undefined macros
    "-Wundef",
}

def abs_kernel_path(rel_path):
    return os.path.normpath(os.path.join(sys.argv[1], rel_path))

if __name__ == '__main__':
    db = None
    with open(sys.argv[2], 'r') as db_f:
        db = json.load(db_f)

    if len(db) != 1:
        sys.exit("Invalid database length: %d" % len(db))

    src_file = db[0]["file"]
    if not src_file.endswith("selfrando.c"):
        sys.exit("Invalid database source file: %s" % src_file)

    out_cflags = []
    for arg in db[0]["arguments"][1:]:
        if arg in ARGUMENT_BLACKLIST:
            continue
        if any(arg.startswith(prefix) for prefix in PREFIX_BLACKLIST):
            continue
        # Ignore anything selfrando-specific
        if "selfrando" in arg:
            continue

        if arg.startswith("./"):
            # Normalize a kernel-relative path
            arg = abs_kernel_path(arg)
        elif arg.startswith("-I./"):
            arg = "-I" + abs_kernel_path(arg[2:])

        out_cflags.append(arg)

    print(" ".join(out_cflags), end='')
