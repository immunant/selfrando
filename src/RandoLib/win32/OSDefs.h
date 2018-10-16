/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the University of California nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <Windows.h>
#include <winternl.h>

// Since at some point we're remapping all of .text as non-executable,
// we need to put all of our code into a separate executable section
// so it can continue to execute.
#define RANDO_SECTION   __declspec(code_seg(".rndtext"))

#define RANDO_ALWAYS_INLINE __forceinline

#define RANDO_PUBLIC_FUNCTION(name, return_type, ...)   \
    extern "C" RANDO_SECTION                            \
    return_type WINAPI _TRaP_##name(__VA_ARGS__)

#define RANDO_MAIN_FUNCTION()  RANDO_PUBLIC_FUNCTION(RandoMain, void, os::Module::Handle asm_module)

#define RANDO_SYS_FUNCTION(library, function, ...)  (os::APIImpl::library##_##function)(__VA_ARGS__)

#define RANDO_ASSERT(cond)      \
    do {                        \
        if (!os::API::kEnableAsserts)\
            break;              \
        if (cond)               \
            break;              \
        os::API::SystemMessage("RandoLib assertion error: '%s' at %s:%d\n", #cond, __FILE__, __LINE__); \
        __debugbreak();         \
    } while (0)
