/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * Copyright (c) 2015-2019 RunSafe Security Inc.
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

#pragma pack(push, 1) // TODO: MSVC-only; use gcc equivalent on Linux
struct RANDO_SECTION Function {
    os::BytePointer undiv_start, div_start;
    size_t size;

    // Base-2 logarithm of alignment
    unsigned undiv_p2align : 6;

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

    // Tiebreaker rank for elems with the same undiv_addr
    int sort_rank() const {
        // If we have multiple functions at the same address, then:
        // 1) All the non-sized ones must come first, so we can set their sizes to 0
        // 2) Non-sized gaps should precede non-sized TRaP functions, so the latter have priority when computing sizes
        // 3) The sized function with non-zero size must come last (if it exists)
        if (!has_size)
            return is_gap ? 1 : 2;
        if (size == 0)
            return 3;
        return 4;
    }
};
#pragma pack(pop)

template<typename T>
struct RANDO_SECTION Vector {
    T *elems;
    size_t num_elems;
    size_t capacity;

    Vector() : elems(nullptr), num_elems(0), capacity(0) { }
    Vector(const Vector&) = delete;
    Vector(const Vector&&) = delete;
    Vector &operator=(const Vector&) = delete;
    Vector &operator=(const Vector&&) = delete;

    void clear() {
        if (elems != nullptr) {
            for (size_t i = 0; i < num_elems; i++)
                elems[i].~T(); // Call the destructor for each initialized element
            os::API::mem_free(elems);
        }
        elems = nullptr;
        num_elems = 0;
        capacity = 0;
    }

    void reserve(size_t new_capacity) {
        if (new_capacity < capacity)
            return;

        auto old_capacity = capacity;
        capacity = new_capacity;
        if (old_capacity == 0) {
            elems = reinterpret_cast<T*>(os::API::mem_alloc(capacity * sizeof(T), true));
        } else {
            elems = reinterpret_cast<T*>(os::API::mem_realloc(elems, capacity * sizeof(T), true));
        }
    }

    void append(const T &val) {
        if (num_elems == capacity)
            grow();
        elems[num_elems++] = val;
    }

    T &operator[](size_t idx) {
        return elems[idx];
    }

    const T &operator[](size_t idx) const {
        return elems[idx];
    }

    template<typename Func>
    void sort(Func compare) {
        os::API::qsort(elems, num_elems, sizeof(T), compare);
    }

    template<typename Func>
    void remove_if(Func remove_index) {
        size_t out = 0;
        for (size_t in = 0; in < num_elems; in++) {
            if (remove_index(in))
                continue;
            if (out < in)
                elems[out] = elems[in];
            out++;
        }
        num_elems = out;
        // TODO: shrink the memory region to save space???
    }

private:
    static constexpr size_t DEFAULT_CAPACITY = 16;

    void grow() {
        if (capacity < DEFAULT_CAPACITY) {
            static_assert(DEFAULT_CAPACITY > 1, "Default vector capacity too small");
            capacity = DEFAULT_CAPACITY;
        } else {
            // Growth factor of 1.5
            capacity += capacity >> 1;
        }
        reserve(capacity);
    }
};

struct RANDO_SECTION FunctionList : public Vector<Function> {
    Function *find_function(os::BytePointer) const;

    // It's unfortunate that we have to use a template here,
    // but it seems we cannot forward-declare os::Module::Relocation
    template<class Reloc>
    void adjust_relocation(Reloc*) const;
};

#endif // __RANDOLIB_H
