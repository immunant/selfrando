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

#ifndef __RANDOLIB_TRAPINFO_H
#define __RANDOLIB_TRAPINFO_H
#pragma once

#include <TrapInfoRelocs.h>

#ifndef RANDO_SECTION
#define RANDO_SECTION
#endif

typedef uint8_t *trap_pointer_t;

#pragma push_macro("SET_FIELD")
#define SET_FIELD(x, field, val)  \
    do {                          \
        if (x) {                  \
            (x)->field = (val);   \
        } else {                  \
            (void)(val);          \
        }                         \
    } while (0)

// FIXME: is uintptr_t the correct type here?
static inline RANDO_SECTION
uintptr_t trap_read_uleb128(trap_pointer_t *trap_ptr) {
    uintptr_t res = 0, shift = 0;
    while (((**trap_ptr) & 0x80) != 0) {
        res += ((**trap_ptr) & 0x7F) << shift;
        shift += 7;
        (*trap_ptr)++;
    }
    res += (**trap_ptr) << shift;
    (*trap_ptr)++;
    return res;
}

static inline RANDO_SECTION
ptrdiff_t trap_read_sleb128(trap_pointer_t *trap_ptr) {
    ptrdiff_t res = 0, shift = 0;
    while (((**trap_ptr) & 0x80) != 0) {
        res += ((**trap_ptr) & 0x7F) << shift;
        shift += 7;
        (*trap_ptr)++;
    }
    res += (**trap_ptr) << shift;
    (*trap_ptr)++;
    shift += 7;

    ptrdiff_t sign_bit = ptrdiff_t(1) << (shift - 1);
    if ((res & sign_bit) != 0)
        res |= -(ptrdiff_t(1) << shift);
    return res;
}

typedef enum {
    TRAP_FUNCTIONS_MARKED = 0x100,
    TRAP_PRE_SORTED = 0x200,
    TRAP_HAS_SYMBOL_SIZE = 0x400,
    TRAP_HAS_DATA_REFS = 0x800,
    TRAP_HAS_RECORD_RELOCS = 0x1000,
    TRAP_HAS_NONEXEC_RELOCS = 0x2000,
    TRAP_HAS_RECORD_PADDING = 0x4000,
    TRAP_PC_RELATIVE_ADDRESSES = 0x8000,
    TRAP_HAS_SYMBOL_P2ALIGN = 0x10000,
} trap_header_flags_t;

// Warning: relies on little-endianness
struct RANDO_SECTION TrapHeader {
public:
    union {
        uint8_t version;
        uint32_t flags;
    };
    // TODO: Extend this structure to contain non-exec relocs vector

#ifdef __cplusplus
    // Do the Trap records also contain size info???
    bool has_symbol_size() const {
        return (flags & TRAP_HAS_SYMBOL_SIZE) != 0;
    }

    bool has_data_refs() const {
        return (flags & TRAP_HAS_DATA_REFS) != 0;
    }

    // Return false if the Trap records are already sorted
    bool needs_sort() const {
        return (flags & TRAP_PRE_SORTED) == 0;
    }

    bool has_record_relocs() const {
        return (flags & TRAP_HAS_RECORD_RELOCS) != 0;
    }

    bool has_nonexec_relocs() const {
        return (flags & TRAP_HAS_NONEXEC_RELOCS) != 0;
    }

    bool has_record_padding() const {
        return (flags & TRAP_HAS_RECORD_PADDING) != 0;
    }

    bool pc_relative_addresses() const {
        return (flags & TRAP_PC_RELATIVE_ADDRESSES) != 0;
    }

    bool has_symbol_p2align() const {
        return (flags & TRAP_HAS_SYMBOL_P2ALIGN) != 0;
    }
#endif // __cplusplus
};
static_assert(sizeof(TrapHeader) == 4, "Invalid size of Header structure");

static inline RANDO_SECTION
int trap_header_has_flag(const TrapHeader *header, int flag) {
    return (header->flags & flag) != 0;
}

static inline RANDO_SECTION
size_t trap_elements_in_symbol(const TrapHeader *header) {
    size_t elems = 1;
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_P2ALIGN))
        elems++;
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_SIZE))
        elems++;
    return elems;
}

static inline RANDO_SECTION
void trap_skip_vector(trap_pointer_t *trap_ptr) {
    while (**trap_ptr)
        (*trap_ptr)++;
    (*trap_ptr)++;
}

class RANDO_SECTION TrapVector {
public:
    TrapVector(trap_pointer_t start, trap_pointer_t end, uintptr_t address)
        : m_start(start), m_end(end), m_address(address) {}

    class Iterator {
    public:
        explicit Iterator(trap_pointer_t trap_ptr, uintptr_t address)
            : m_trap_ptr(trap_ptr), m_address(address) {}
        Iterator(const Iterator&) = default;
        Iterator &operator=(const Iterator&) = default;

        // Preincrement
        Iterator &operator++() {
            auto delta = trap_read_uleb128(&m_trap_ptr);
            m_address += delta;
            return *this;
        }

        // FIXME: better return type
        uintptr_t operator*() const {
            // FIXME: would be faster to add curr_delta to m_address in advance
            // so this turns into a simple read from m_address
            auto tmp_trap_ptr = m_trap_ptr;
            auto curr_delta = trap_read_uleb128(&tmp_trap_ptr);
            return m_address + curr_delta;
        }

        bool operator==(const Iterator &it) const {
            return m_trap_ptr == it.m_trap_ptr;
        }

        bool operator!=(const Iterator &it) const {
            return m_trap_ptr != it.m_trap_ptr;
        }

    private:
        trap_pointer_t m_trap_ptr;
        uintptr_t m_address;
    };

    Iterator begin() {
        return Iterator(m_start, m_address);
    }

    Iterator end() {
        RANDO_ASSERT(m_end[0] == 0 || m_start == m_end);
        // FIXME: use MAX_INT instead of 0???
        return Iterator(m_end, 0);
    }

private:
    trap_pointer_t m_start, m_end;
    uintptr_t m_address;
};

struct RANDO_SECTION TrapReloc {
    uintptr_t address;
    size_t type;
    // FIXME: figure out a way to not store these in memory
    // when they're not needed
    uintptr_t symbol;
    ptrdiff_t addend;
};

static inline RANDO_SECTION
int trap_read_reloc(const TrapHeader *header,
                    trap_pointer_t *trap_ptr,
                    uintptr_t *address,
                    TrapReloc *reloc) {
    uintptr_t curr_delta = trap_read_uleb128(trap_ptr);
    size_t curr_type = (size_t)trap_read_uleb128(trap_ptr);
    if (curr_delta == 0 && curr_type == 0)
        return 0;

    trap_reloc_info_t extra_info = trap_reloc_info(curr_type);
    uintptr_t curr_symbol = 0;
    ptrdiff_t curr_addend = 0;
    if ((extra_info & TRAP_RELOC_SYMBOL) != 0) {
        if (trap_header_has_flag(header, TRAP_PC_RELATIVE_ADDRESSES)) {
            ptrdiff_t delta = *(ptrdiff_t*)*trap_ptr;
#if !RANDOLIB_IS_ARM64
            // We use GOT-relative offsets
            // We add the GOT base later inside of Address::to_ptr()
            curr_symbol = (uintptr_t)delta;
#else
            curr_symbol = (uintptr_t)((*trap_ptr) + delta);
#endif
            *trap_ptr += sizeof(ptrdiff_t);
        } else {
            curr_symbol = *(uintptr_t*)*trap_ptr;
            *trap_ptr += sizeof(uintptr_t);
        }
    }
    if ((extra_info & TRAP_RELOC_ADDEND) != 0)
        curr_addend = trap_read_sleb128(trap_ptr);

    *address += curr_delta;
    SET_FIELD(reloc, address, (*address));
    SET_FIELD(reloc, type, curr_type);
    SET_FIELD(reloc, symbol, curr_symbol);
    SET_FIELD(reloc, addend, curr_addend);
    return 1;
}

static inline RANDO_SECTION
void trap_skip_reloc_vector(const TrapHeader *trap_header,
                            trap_pointer_t *trap_ptr) {
    uintptr_t address = 0;
    int cont = 0;
    do {
        cont = trap_read_reloc(trap_header, trap_ptr, &address, nullptr);
    } while (cont);
}

#pragma pack(push, 1)
struct RANDO_SECTION TrapSymbol {
    uintptr_t address;
    uintptr_t alignment;
    size_t size;
};
#pragma pack(pop)

static inline RANDO_SECTION
int trap_read_symbol(const TrapHeader *header,
                     trap_pointer_t *trap_ptr,
                     uintptr_t *address,
                     TrapSymbol *symbol) {

    // FIXME: would be faster to add curr_delta to m_address in advance
    // so this turns into a simple read from m_address
    uintptr_t curr_delta = trap_read_uleb128(trap_ptr);
    uintptr_t curr_size = 0;
    uintptr_t curr_p2align = 0;
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_SIZE))
        curr_size = trap_read_uleb128(trap_ptr);
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_P2ALIGN))
        curr_p2align = trap_read_uleb128(trap_ptr);
    if (curr_delta == 0 && curr_size == 0 && curr_p2align == 0)
        return 0;

    *address += curr_delta;
    SET_FIELD(symbol, address, *address);
    SET_FIELD(symbol, alignment, (uintptr_t(1) << curr_p2align));
    SET_FIELD(symbol, size, (size_t)curr_size);
    return 1;
}

static inline RANDO_SECTION
void trap_skip_symbol_vector(const TrapHeader *header,
                             trap_pointer_t *trap_ptr) {
    uintptr_t address = 0;
    int cont = 0;
    do {
        cont = trap_read_symbol(header, trap_ptr, &address, nullptr);
    } while (cont);
}

struct RANDO_SECTION TrapRelocVector {
public:
    TrapRelocVector() = delete;
    TrapRelocVector(trap_pointer_t start, trap_pointer_t end,
                    uintptr_t address, const TrapHeader *header)
        : m_start(start), m_end(end), m_address(address), m_header(header) {}

    class Iterator {
    public:
        explicit Iterator(trap_pointer_t trap_ptr, uintptr_t address,
                          const TrapHeader *header)
            : m_trap_ptr(trap_ptr), m_address(address), m_header(header) {}
        Iterator(const Iterator&) = default;
        Iterator &operator=(const Iterator&) = default;

        // Preincrement
        Iterator &operator++() {
            trap_read_reloc(m_header, &m_trap_ptr, &m_address, nullptr);
            return *this;
        }

        const TrapReloc operator*() const {
            TrapReloc reloc;
            auto tmp_trap_ptr = m_trap_ptr;
            auto tmp_address = m_address;
            trap_read_reloc(m_header, &tmp_trap_ptr, &tmp_address, &reloc);
            return reloc;
        }

        bool operator==(const Iterator &it) const {
            return m_trap_ptr == it.m_trap_ptr;
        }

        bool operator!=(const Iterator &it) const {
            return m_trap_ptr != it.m_trap_ptr;
        }

    private:
        trap_pointer_t m_trap_ptr;
        uintptr_t m_address;
        const TrapHeader *m_header;
    };

    Iterator begin() {
        return Iterator(m_start, m_address, m_header);
    }

    Iterator end() {
        RANDO_ASSERT((m_end[0] == 0 && m_end[1] == 0) || m_start == m_end);
        // FIXME: use MAX_INT instead of 0???
        return Iterator(m_end, 0, nullptr);
    }

private:
    trap_pointer_t m_start, m_end;
    uintptr_t m_address;
    const TrapHeader *m_header;
};

struct RANDO_SECTION TrapAddnHeaderInfo {
private:
    trap_pointer_t reloc_start, reloc_end = nullptr;
    const TrapHeader *header_start_ptr;
    trap_pointer_t header_end_ptr = nullptr;

public:
    TrapAddnHeaderInfo() {} // Invalid struct constructor

    TrapAddnHeaderInfo(const TrapHeader* header) {
        header_start_ptr = header;
        auto curr_ptr = reinterpret_cast<trap_pointer_t>(const_cast<TrapHeader*>(header + 1));
        reloc_start = reloc_end = curr_ptr;
        if (header->has_nonexec_relocs()) {
            trap_skip_reloc_vector(header, &curr_ptr);
            reloc_end = curr_ptr - 2;
        }
        header_end_ptr = curr_ptr;
    }

    trap_pointer_t header_end() const {
        RANDO_ASSERT(header_end_ptr != nullptr);
        return header_end_ptr;
    }

    TrapRelocVector nonexec_relocations() const {
        RANDO_ASSERT(reloc_end != nullptr);
        // TODO: do we want to introduce a base address for these???
        // (so they don't start from zero)
        return TrapRelocVector(reloc_start, reloc_end, 0, header_start_ptr);
    }
};

// TODO: maybe we can merge this with TrapVector (using templates???)
class RANDO_SECTION TrapSymbolVector {
public:
    TrapSymbolVector(const TrapHeader *header, trap_pointer_t start, trap_pointer_t end, uintptr_t address)
        : m_header(header), m_start(start), m_end(end), m_address(address) {}

    class Iterator {
    public:
        explicit Iterator(const TrapHeader *header, trap_pointer_t trap_ptr, uintptr_t address)
            : m_header(header), m_trap_ptr(trap_ptr), m_address(address) {}
        Iterator(const Iterator&) = default;
        Iterator &operator=(const Iterator&) = default;

        // Preincrement
        Iterator &operator++() {
            trap_read_symbol(m_header, &m_trap_ptr, &m_address, nullptr);
            return *this;
        }

        TrapSymbol operator*() const {
            TrapSymbol symbol;
            auto tmp_trap_ptr = m_trap_ptr;
            auto tmp_address = m_address;
            trap_read_symbol(m_header, &tmp_trap_ptr, &tmp_address, &symbol);
            return symbol;
        }

        bool operator==(const Iterator &it) const {
            return m_trap_ptr == it.m_trap_ptr;
        }

        bool operator!=(const Iterator &it) const {
            return m_trap_ptr != it.m_trap_ptr;
        }

    private:
        const TrapHeader *m_header;
        trap_pointer_t m_trap_ptr;
        uintptr_t m_address;
    };

    Iterator begin() {
        return Iterator(m_header, m_start, m_address);
    }

    Iterator end() {
        RANDO_ASSERT(m_end[0] == 0 || m_start == m_end);
        RANDO_ASSERT((!m_header->has_symbol_p2align() && !m_header->has_symbol_size()) ||
                     m_end[1] == 0);
        // FIXME: use MAX_INT instead of 0???
        return Iterator(m_header, m_end, 0);
    }

private:
    const TrapHeader *m_header;
    trap_pointer_t m_start, m_end;
    uintptr_t m_address;
};

class RANDO_SECTION TrapRecord {
public:
    TrapRecord(const TrapHeader *header, trap_pointer_t record_start, trap_pointer_t record_end)
               : m_header(header), m_start(record_start), m_end(record_end) {
        auto trap_ptr = record_start;
        if (header->pc_relative_addresses()) {
            auto delta_ptr = reinterpret_cast<ptrdiff_t*>(trap_ptr);
            trap_ptr += sizeof(*delta_ptr);
            auto delta = *delta_ptr;
#if !RANDOLIB_IS_ARM64
            // See comment above on GOT-relative relocations
            m_address = static_cast<uintptr_t>(delta);
#else
            m_address = reinterpret_cast<uintptr_t>(delta_ptr) + delta;
#endif
        } else {
            auto addr_ptr = reinterpret_cast<uintptr_t*>(trap_ptr);
            trap_ptr += sizeof(*addr_ptr); // FIXME: 8 bytes on x64???
            m_address = *addr_ptr;
        }
        // Parse symbol vector
        m_symbol_start = trap_ptr;
        // We include the first symbol in the symbol vector
        // and we set m_address to the section address
        auto first_sym_ofs = trap_read_uleb128(&trap_ptr);
        m_address -= first_sym_ofs;
        if (header->has_symbol_size())
            trap_read_uleb128(&trap_ptr);
        if (header->has_symbol_p2align())
            trap_read_uleb128(&trap_ptr);
        trap_skip_symbol_vector(header, &trap_ptr);
        m_symbol_end = trap_ptr - trap_elements_in_symbol(header);
        // Relocations vector
        m_reloc_start = m_reloc_end = trap_ptr;
        if (header->has_record_relocs()) {
            trap_skip_reloc_vector(header, &trap_ptr);
            m_reloc_end = trap_ptr - 2;
        }
        // Data references
        m_data_refs_start = m_data_refs_end = trap_ptr;
        if (header->has_data_refs()) {
            trap_skip_vector(&trap_ptr);
            m_data_refs_end = trap_ptr - 1;
        }
        if (header->has_record_padding()) {
            m_padding_ofs = trap_read_uleb128(&trap_ptr);
            m_padding_size = trap_read_uleb128(&trap_ptr);
        }
        // TODO: also read in the data_refs
        RANDO_ASSERT(trap_ptr == m_end);
    }

    uintptr_t base_address() const {
        return m_address;
    }

    // TODO: find a good name for this; "symbols" isn't perfectly accurate
    // but "functions" wouldn't be either (we may wanna use these for basic blocks instead)
    TrapSymbolVector symbols() {
        return TrapSymbolVector(m_header, m_symbol_start, m_symbol_end, m_address);
    }

    TrapRelocVector relocations() {
        return TrapRelocVector(m_reloc_start, m_reloc_end, m_address, m_header);
    }

    TrapVector data_refs() {
        RANDO_ASSERT(m_header->has_data_refs());
        return TrapVector(m_data_refs_start, m_data_refs_end, m_address);
    }

    uintptr_t padding_address() {
        RANDO_ASSERT(m_header->has_record_padding());
        return m_address + m_padding_ofs;
    }

    size_t padding_size() {
        RANDO_ASSERT(m_header->has_record_padding());
        return m_padding_size;
    }

private:
    const TrapHeader *m_header;
    trap_pointer_t m_start, m_end;
    uintptr_t m_address, m_first_sym_ofs, m_padding_ofs;
    size_t m_padding_size;
    trap_pointer_t m_symbol_start, m_symbol_end;
    trap_pointer_t m_reloc_start, m_reloc_end;
    trap_pointer_t m_data_refs_start, m_data_refs_end;
};

class RANDO_SECTION TrapInfo {
public:
    explicit TrapInfo(trap_pointer_t trap_data, size_t trap_size) {
        m_trap_data = trap_data;
        m_trap_size = trap_size;
        ReadHeader();
    }

    class Iterator {
    public:
        Iterator(const TrapHeader *header, trap_pointer_t trap_ptr, bool end)
            : m_header(header), m_trap_ptr(trap_ptr), m_end(end) {
            AdvanceNext();
        }
        Iterator(const Iterator &it) = default;
        Iterator &operator=(const Iterator &it) = default;

        // Preincrement
        Iterator &operator++() {
            m_trap_ptr = m_trap_next;
            AdvanceNext();
            return *this;
        }

        TrapRecord operator*() const {
            return TrapRecord(m_header, m_trap_ptr, m_trap_next);
        }

        bool operator==(const Iterator &it) const {
            return m_trap_ptr == it.m_trap_ptr;
        }

        bool operator!=(const Iterator &it) const {
            return m_trap_ptr != it.m_trap_ptr;
        }

    private:
        const TrapHeader *m_header;
        trap_pointer_t m_trap_ptr, m_trap_next;
        bool m_end;

        void AdvanceNext() {
            m_trap_next = m_trap_ptr;
            if (!m_end) {
                m_trap_next += m_header->pc_relative_addresses()
                               ? sizeof(ptrdiff_t) : sizeof(uintptr_t);
                trap_read_uleb128(&m_trap_next);
                if (m_header->has_symbol_size())
                    trap_read_uleb128(&m_trap_next);
                if (m_header->has_symbol_p2align())
                    trap_read_uleb128(&m_trap_next);
                trap_skip_symbol_vector(m_header, &m_trap_next);
                if (m_header->has_record_relocs())
                    trap_skip_reloc_vector(m_header, &m_trap_next);
                if (m_header->has_data_refs())
                    trap_skip_vector(&m_trap_next);
                if (m_header->has_record_padding()) {
                    trap_read_uleb128(&m_trap_next);
                    trap_read_uleb128(&m_trap_next);
                }
            }
        }
    };

    Iterator begin() {
        return Iterator(m_header, m_trap_records, false);
    }

    Iterator end() {
        return Iterator(m_header, m_trap_data + m_trap_size, true);
    }

    const TrapHeader *header() const {
        return m_header;
    }


    const TrapAddnHeaderInfo &addn_info() const {
        return m_addn_info;
    }

private:
    trap_pointer_t m_trap_data, m_trap_records;
    size_t m_trap_size;
    TrapHeader *m_header;
    TrapAddnHeaderInfo m_addn_info;

    void ReadHeader() {
        m_header = reinterpret_cast<TrapHeader*>(m_trap_data);
        m_addn_info = TrapAddnHeaderInfo(m_header);
        m_trap_records = m_addn_info.header_end();
    }
};

#pragma pop_macro("SET_FIELD")

#endif // __RANDOLIB_TRAPINFO_H
