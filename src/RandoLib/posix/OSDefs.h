/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <errno.h>

// FIXME: gcc doesn't support assigning an entire class to a section
// so we'll either have to solve this using linker scripts
// or include RandoLib as an external shared library
#define RANDO_SECTION

#if RANDOLIB_IS_SHARED
#define RANDO_PUBLIC  __attribute__((visibility("default")))
#define RANDO_PUBLIC_FUNCTION(name, return_type, ...)   \
    extern "C" RANDO_PUBLIC RANDO_SECTION               \
    return_type _TRaP_##name(__VA_ARGS__)

#else // RANDOLIB_IS_SHARED
#define RANDO_PUBLIC  __attribute__((visibility("hidden")))
// We don't need the _TRaP_ prefix for public functions, since objcopy adds it
#define RANDO_PUBLIC_FUNCTION(name, return_type, ...)   \
    extern "C" RANDO_PUBLIC RANDO_SECTION               \
    return_type name(__VA_ARGS__)
#endif // RANDOLIB_IS_SHARED

#define RANDO_MAIN_FUNCTION()   RANDO_PUBLIC_FUNCTION(RandoMain, void, os::Module::Handle asm_module)

#define RANDO_ALWAYS_INLINE __attribute__((always_inline)) inline

// TODO
//#define RANDO_ASSERT(cond) assert(cond)

#define RANDO_ASSERT_STR(x)        #x
#define RANDO_ASSERT_STRM(x)       RANDO_ASSERT_STR(x)
#define RANDO_ASSERT(cond)  ((cond) ? (void)0 \
                                    : (os::API::debug_printf<0>(__FILE__ ":" RANDO_ASSERT_STRM(__LINE__) " assertion failed: " #cond ), __builtin_trap()))
