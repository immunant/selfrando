/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <link.h>

// FIXME: gcc doesn't support assigning an entire class to a section
// so we'll either have to solve this using linker scripts
// or include RandoLib as an external shared library
#define RANDO_SECTION

#if RANDOLIB_IS_SHARED
#define RANDO_PUBLIC  __attribute__((visibility("default")))
#else
#define RANDO_PUBLIC  __attribute__((visibility("hidden")))
#endif

#define RANDO_ALWAYS_INLINE __attribute__((always_inline)) inline

#define RANDO_MAIN_FUNCTION()  extern "C" RANDO_PUBLIC void _TRaP_RandoMain(os::Module::Handle asm_module)

// TODO
//#define RANDO_ASSERT(cond) assert(cond)

#define RANDO_ASSERT_STR(x)        #x
#define RANDO_ASSERT_STRM(x)       RANDO_ASSERT_STR(x)
#define RANDO_ASSERT(cond)  ((cond) ? (void)0 \
                                    : (os::API::debug_printf<0>(__FILE__ ":" RANDO_ASSERT_STRM(__LINE__) " assertion failed: " #cond ), __builtin_trap()))
