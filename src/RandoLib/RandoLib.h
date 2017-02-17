/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * Copyright (c) 2015-2017 Immunant Inc.
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

#ifndef __RANDOLIB_H
#define __RANDOLIB_H
#pragma once

#include <OS.h>

#pragma pack(1) // TODO: MSVC-only; use gcc equivalent on Linux
struct RANDO_SECTION Function {
    os::BytePointer undiv_start, div_start;
    size_t size;
    size_t undiv_alignment;
    size_t alignment_padding;

    // Boolean flags
    bool skip_copy  : 1;
    bool from_trap  : 1;
    bool is_padding : 1;
    bool is_gap     : 1;
    bool has_size   : 1;

    ptrdiff_t div_delta() const {
        return skip_copy ? 0 : (div_start - undiv_start);
    }

    os::BytePointer inline undiv_end() const {
        return undiv_start + size;
    }

    os::BytePointer inline div_end() const {
        return div_start + size;
    }

    bool undiv_contains(os::BytePointer addr) const {
        return addr >= undiv_start && addr < undiv_end();
    }

    bool div_contains(os::BytePointer addr) const {
        return addr >= div_start && addr < div_end();
    }

    os::BytePointer post_div_address(os::BytePointer addr) const {
        RANDO_ASSERT(undiv_contains(addr));
        return (addr + div_delta());
    }

    // Tiebreaker rank for functions with the same undiv_addr
    int sort_rank() const {
        // Skipped functions and non-TRaP functions should
        // come before regular TRaP ones
        if (!from_trap)
            return 1;
        if (skip_copy)
            return 1;
        return 2;
    }
};

struct RANDO_SECTION FunctionList {
    Function *functions;
    size_t num_funcs;

    FunctionList() : functions(nullptr), num_funcs(0) { }

    void allocate() {
        if (functions != nullptr)
            os::API::MemFree(functions);
        functions = reinterpret_cast<Function*>(os::API::MemAlloc(num_funcs * sizeof(Function), true));
    }

    void free() {
        if (functions != nullptr)
            os::API::MemFree(functions);
        functions = nullptr;
    }

    void extend(size_t num_extra) {
        if (num_extra == 0)
            return;
        if (functions == nullptr) {
            num_funcs = num_extra;
            allocate();
            return;
        }

        Function *old_funcs = functions;
        num_funcs += num_extra;
        functions = reinterpret_cast<Function*>(os::API::MemAlloc(num_funcs * sizeof(Function), true));
        os::API::MemCpy(functions, old_funcs, (num_funcs - num_extra) * sizeof(Function));
        os::API::MemFree(old_funcs);
    }

    Function &operator[](size_t idx) {
        return functions[idx];
    }

    Function *FindFunction(os::BytePointer);
};

#endif // __RANDOLIB_H
