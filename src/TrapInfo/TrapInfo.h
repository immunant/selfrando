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

#ifndef RANDO_ASSERT
#define RANDO_ASSERT(x)
#endif

// Our own C and C++-compatible cast macros,
// one that is equivalent with static_cast
// and one with reinterpret_cast
#pragma push_macro("SCAST")
#pragma push_macro("RCAST")
#ifdef __cplusplus
#define SCAST(type, val) (static_cast<type>(val))
#define RCAST(type, val) (reinterpret_cast<type>(val))
#else
#define SCAST(type, val) ((type) (val))
#define RCAST(type, val) ((type) (val))
#endif

struct trap_header_t;

typedef uint8_t *trap_pointer_t;
typedef int (*trap_read_func_t)(const struct trap_header_t*,
                                trap_pointer_t*,
                                uint64_t*,
                                void*);

#pragma push_macro("SET_FIELD")
#define SET_FIELD(x, field, val)  \
    do {                          \
        if (x) {                  \
            (x)->field = (val);   \
        } else {                  \
            (void)(val);          \
        }                         \
    } while (0)

// FIXME: is uint64_t the correct type here?
static inline RANDO_SECTION
uint64_t trap_read_uleb128(trap_pointer_t *trap_ptr) {
    uint64_t res = 0, shift = 0;
    while (((**trap_ptr) & 0x80) != 0) {
        res += (SCAST(uint64_t, **trap_ptr) & 0x7F) << shift;
        shift += 7;
        (*trap_ptr)++;
    }
    res += SCAST(uint64_t, **trap_ptr) << shift;
    (*trap_ptr)++;
    return res;
}

static inline RANDO_SECTION
int64_t trap_read_sleb128(trap_pointer_t *trap_ptr) {
    int64_t res = 0, shift = 0;
    while (((**trap_ptr) & 0x80) != 0) {
        res += (SCAST(int64_t, **trap_ptr) & 0x7F) << shift;
        shift += 7;
        (*trap_ptr)++;
    }
    res += SCAST(int64_t, **trap_ptr) << shift;
    (*trap_ptr)++;
    shift += 7;

    int64_t sign_bit = SCAST(int64_t, 1) << (shift - 1);
    if ((res & sign_bit) != 0)
        res |= -(SCAST(int64_t, 1) << shift);
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
    TRAP_HAS_POINTER_SIZE = 0x20000,
} trap_header_flags_t;

// Warning: relies on little-endianness
#pragma pack(push, 1)
struct RANDO_SECTION trap_header_t {
    union {
        uint8_t version;
        uint32_t flags;
    };
    uint64_t pointer_size;

    trap_pointer_t reloc_start, reloc_end;
    trap_pointer_t record_start;

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
#pragma pack(pop)

static inline RANDO_SECTION
int trap_header_has_flag(const struct trap_header_t *header, uint32_t flag) {
    return (header->flags & flag) != 0;
}

static inline RANDO_SECTION
size_t trap_elements_in_symbol(const struct trap_header_t *header) {
    size_t elems = 1;
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_P2ALIGN))
        elems++;
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_SIZE))
        elems++;
    return elems;
}

static inline RANDO_SECTION
uint64_t trap_read_address(const struct trap_header_t *header,
                            trap_pointer_t *trap_ptr) {
    uint64_t addr;
    if (header->pointer_size == 32) {
        addr = SCAST(uint64_t, *RCAST(int32_t*, *trap_ptr));
    } else {
        addr = *RCAST(uint64_t*, *trap_ptr);
    }
    if (trap_header_has_flag(header, TRAP_PC_RELATIVE_ADDRESSES)) {
#if !RANDOLIB_IS_ARM64
        // We use GOT-relative offsets
        // We add the GOT base later inside of Address::to_ptr()
#else
        addr = SCAST(uint64_t, *trap_ptr + SCAST(int64_t, addr));
#endif
    }
    *trap_ptr += header->pointer_size / 8;
    return addr;
}

static inline RANDO_SECTION
void trap_skip_uleb128_vector(trap_pointer_t *trap_ptr) {
    while (**trap_ptr)
        (*trap_ptr)++;
    (*trap_ptr)++;
}

static inline RANDO_SECTION
void trap_skip_vector(const struct trap_header_t *trap_header,
                      trap_pointer_t *trap_ptr,
                      trap_read_func_t read_func) {
    uint64_t address = 0;
    int cont = 0;
    do {
        cont = (*read_func)(trap_header, trap_ptr, &address, NULL);
    } while (cont);
}

#pragma pack(push, 1)
struct RANDO_SECTION trap_reloc_t {
    uint64_t address;
    uint64_t type;
    // FIXME: figure out a way to not store these in memory
    // when they're not needed
    uint64_t symbol;
    int64_t addend;
};
#pragma pack(pop)

static inline RANDO_SECTION
int trap_read_reloc(const struct trap_header_t *header,
                    trap_pointer_t *trap_ptr,
                    uint64_t *address,
                    void *data) {
    struct trap_reloc_t *reloc = RCAST(struct trap_reloc_t*, data);
    uint64_t curr_delta = trap_read_uleb128(trap_ptr);
    uint64_t curr_type = trap_read_uleb128(trap_ptr);
    int end = (curr_delta == 0 && curr_type == 0);

    int extra_info = trap_reloc_info(curr_type);
    uint64_t curr_symbol = 0;
    int64_t curr_addend = 0;
    if (!end) {
        if ((extra_info & TRAP_RELOC_SYMBOL) != 0)
            curr_symbol = trap_read_address(header, trap_ptr);
        if ((extra_info & TRAP_RELOC_ADDEND) != 0)
            curr_addend = trap_read_sleb128(trap_ptr);
    }

    *address += curr_delta;
    SET_FIELD(reloc, address, (*address));
    SET_FIELD(reloc, type,    curr_type);
    SET_FIELD(reloc, symbol,  curr_symbol);
    SET_FIELD(reloc, addend,  curr_addend);
    return !end;
}

#pragma pack(push, 1)
struct RANDO_SECTION trap_symbol_t {
    uint64_t address;
    uint64_t alignment;
    uint64_t size;
};
#pragma pack(pop)

static inline RANDO_SECTION
int trap_read_symbol(const struct trap_header_t *header,
                     trap_pointer_t *trap_ptr,
                     uint64_t *address,
                     void *data) {
    struct trap_symbol_t *symbol = RCAST(struct trap_symbol_t*, data);

    // FIXME: would be faster to add curr_delta to m_address in advance
    // so this turns into a simple read from m_address
    uint64_t curr_delta = trap_read_uleb128(trap_ptr);
    uint64_t curr_size = 0;
    uint64_t curr_p2align = 0;
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_SIZE))
        curr_size = trap_read_uleb128(trap_ptr);
    if (trap_header_has_flag(header, TRAP_HAS_SYMBOL_P2ALIGN))
        curr_p2align = trap_read_uleb128(trap_ptr);

    int end = (curr_delta == 0 && curr_size == 0 && curr_p2align == 0);
    *address += curr_delta;
    SET_FIELD(symbol, address,   *address);
    SET_FIELD(symbol, alignment, (SCAST(uint64_t, 1) << curr_p2align));
    SET_FIELD(symbol, size,      curr_size);
    return !end;
}

static inline RANDO_SECTION
int trap_read_header(const struct trap_header_t *header,
                     trap_pointer_t *trap_ptr,
                     uint64_t *address,
                     void *data) {
    (void)address;

    // FIXME: assert that data == header
    struct trap_header_t *headerw = RCAST(struct trap_header_t*, data);
    uint32_t flags = *RCAST(uint32_t*, *trap_ptr);
    SET_FIELD(headerw, flags, flags);
    *trap_ptr += sizeof(uint32_t);

    SET_FIELD(headerw, reloc_start, *trap_ptr);
    if (flags & TRAP_HAS_NONEXEC_RELOCS) {
        trap_skip_vector(header, trap_ptr, trap_read_reloc);
        SET_FIELD(headerw, reloc_end, (*trap_ptr - 2));
    } else {
        SET_FIELD(headerw, reloc_end, *trap_ptr);
    }
    if (flags & TRAP_HAS_POINTER_SIZE) {
        uint64_t pointer_size = trap_read_uleb128(trap_ptr);
        SET_FIELD(headerw, pointer_size, pointer_size);
    } else {
        // If we don't have the pointer size in TRaP info,
        // assume it's for the native architecture
        SET_FIELD(headerw, pointer_size, sizeof(void*));
    }
    SET_FIELD(headerw, record_start, *trap_ptr);
    return 1;
}

#ifdef __cplusplus
template<typename DataType>
class RANDO_SECTION TrapIterator {
public:
    explicit TrapIterator(const struct trap_header_t *header,
                          trap_pointer_t trap_ptr,
                          uint64_t address,
                          const trap_read_func_t func)
        : m_header(header), m_trap_ptr(trap_ptr),
          m_address(address), m_func(func) {}
    TrapIterator(const TrapIterator&) = default;
    TrapIterator &operator=(const TrapIterator&) = default;

    // Preincrement
    TrapIterator &operator++() {
        (*m_func)(m_header, &m_trap_ptr, &m_address, NULL);
        return *this;
    }

    DataType operator*() const {
        DataType data;
        auto tmp_trap_ptr = m_trap_ptr;
        auto tmp_address = m_address;
        (*m_func)(m_header, &tmp_trap_ptr, &tmp_address, &data);
        return data;
    }

    bool operator==(const TrapIterator &it) const {
        return m_trap_ptr == it.m_trap_ptr;
    }

    bool operator!=(const TrapIterator &it) const {
        return m_trap_ptr != it.m_trap_ptr;
    }

private:
    const struct trap_header_t *m_header;
    trap_pointer_t m_trap_ptr;
    uint64_t m_address;
    const trap_read_func_t m_func;
};

class RANDO_SECTION TrapVector {
public:
    TrapVector(const struct trap_header_t *header, trap_pointer_t start,
               trap_pointer_t end, uint64_t address)
        : m_header(header), m_start(start),
          m_end(end), m_address(address) {}

private:
    // Reader function to pass to TrapIterator
    static int read_element(const struct trap_header_t *header,
                            trap_pointer_t *trap_ptr,
                            uint64_t *address,
                            void *data) {
        (void) header; // Eliminate unused warning
        auto delta = trap_read_uleb128(trap_ptr);
        *address += delta;
        if (data)
            *RCAST(uint64_t*, data) = *address;
        return 1;
    }

public:
    TrapIterator<uint64_t> begin() {
        return TrapIterator<uint64_t>(m_header, m_start, m_address,
                                       read_element);
    }

    TrapIterator<uint64_t> end() {
        RANDO_ASSERT(m_end[0] == 0 || m_start == m_end);
        // FIXME: use MAX_INT instead of 0???
        return TrapIterator<uint64_t>(m_header, m_end, 0,
                                       read_element);
    }

private:
    const struct trap_header_t *m_header;
    trap_pointer_t m_start, m_end;
    uint64_t m_address;
};

class RANDO_SECTION TrapRelocVector {
public:
    TrapRelocVector() = delete;
    TrapRelocVector(trap_pointer_t start, trap_pointer_t end,
                    uint64_t address, const struct trap_header_t *header)
        : m_start(start), m_end(end), m_address(address), m_header(header) {}

    TrapIterator<trap_reloc_t> begin() {
        return TrapIterator<trap_reloc_t>(m_header, m_start, m_address,
                                          trap_read_reloc);
    }

    TrapIterator<trap_reloc_t> end() {
        RANDO_ASSERT((m_end[0] == 0 && m_end[1] == 0) || m_start == m_end);
        // FIXME: use MAX_INT instead of 0???
        return TrapIterator<trap_reloc_t>(m_header, m_end, 0,
                                          trap_read_reloc);
    }

private:
    trap_pointer_t m_start, m_end;
    uint64_t m_address;
    const struct trap_header_t *m_header;
};

// TODO: maybe we can merge this with TrapVector (using templates???)
class RANDO_SECTION TrapSymbolVector {
public:
    TrapSymbolVector(const struct trap_header_t *header, trap_pointer_t start, trap_pointer_t end, uint64_t address)
        : m_header(header), m_start(start), m_end(end), m_address(address) {}

    TrapIterator<trap_symbol_t> begin() {
        return TrapIterator<trap_symbol_t>(m_header, m_start, m_address,
                                           trap_read_symbol);
    }

    TrapIterator<trap_symbol_t> end() {
        RANDO_ASSERT(m_end[0] == 0 || m_start == m_end);
        RANDO_ASSERT((!m_header->has_symbol_p2align() && !m_header->has_symbol_size()) ||
                     m_end[1] == 0);
        // FIXME: use MAX_INT instead of 0???
        return TrapIterator<trap_symbol_t>(m_header, m_end, 0,
                                           trap_read_symbol);
    }

private:
    const struct trap_header_t *m_header;
    trap_pointer_t m_start, m_end;
    uint64_t m_address;
};
#endif // __cplusplus

#pragma pack(push, 1)
struct RANDO_SECTION trap_record_t {
    const struct trap_header_t *header; // TODO: get rid of this
    uint64_t address;
    struct trap_symbol_t first_symbol;
    uint64_t padding_ofs, padding_size;
    trap_pointer_t symbol_start, symbol_end;
    trap_pointer_t reloc_start, reloc_end;
    trap_pointer_t data_refs_start, data_refs_end;

#ifdef __cplusplus
    // TODO: find a good name for this; "symbols" isn't perfectly accurate
    // but "functions" wouldn't be either (we may wanna use these for basic blocks instead)
    TrapSymbolVector symbols() {
        return TrapSymbolVector(header, symbol_start, symbol_end, address);
    }

    TrapRelocVector relocations() {
        return TrapRelocVector(reloc_start, reloc_end, address, header);
    }

    TrapVector data_refs() {
        return TrapVector(header, data_refs_start, data_refs_end, address);
    }

    uint64_t padding_address() {
        return address + padding_ofs;
    }
#endif // __cplusplus
};
#pragma pack(pop)

static inline RANDO_SECTION
int trap_read_record(const struct trap_header_t *header,
                     trap_pointer_t *trap_ptr,
                     uint64_t *address,
                     void *data) {
    struct trap_record_t *record = RCAST(struct trap_record_t*, data);
    uint64_t base_address = *address;
    uint64_t record_address = trap_read_address(header, trap_ptr);
    record_address += base_address;
    SET_FIELD(record, header, header);
    SET_FIELD(record, address, record_address);
    // Parse symbol vector
    SET_FIELD(record, symbol_start, *trap_ptr);
    // We include the first symbol in the symbol vector
    // and we set m_address to the section address
    uint64_t tmp_address = 0;
    if (record) {
        trap_read_symbol(header, trap_ptr, &tmp_address,
                         &record->first_symbol);
        record->address -= record->first_symbol.address;
        record->first_symbol.address += record->address;
    } else {
        trap_read_symbol(header, trap_ptr, &tmp_address, NULL);
    }
    trap_skip_vector(header, trap_ptr, trap_read_symbol);
    SET_FIELD(record, symbol_end, (*trap_ptr - trap_elements_in_symbol(header)));
    // Relocations vector
    SET_FIELD(record, reloc_start, *trap_ptr);
    if (trap_header_has_flag(header, TRAP_HAS_RECORD_RELOCS)) {
        trap_skip_vector(header, trap_ptr, trap_read_reloc);
        SET_FIELD(record, reloc_end, (*trap_ptr - 2));
    } else {
        SET_FIELD(record, reloc_end, *trap_ptr);
    }
    // Data references
    SET_FIELD(record, data_refs_start, *trap_ptr);
    if (trap_header_has_flag(header, TRAP_HAS_DATA_REFS)) {
        trap_skip_uleb128_vector(trap_ptr);
        SET_FIELD(record, data_refs_end, (*trap_ptr - 2));
    } else {
        SET_FIELD(record, data_refs_end, *trap_ptr);
    }
    if (trap_header_has_flag(header, TRAP_HAS_RECORD_PADDING)) {
        SET_FIELD(record, padding_ofs,  trap_read_uleb128(trap_ptr));
        SET_FIELD(record, padding_size, trap_read_uleb128(trap_ptr));
    } else {
        SET_FIELD(record, padding_ofs, 0);
        SET_FIELD(record, padding_size, 0);
    }
    return 1;
}

#ifdef __cplusplus
class RANDO_SECTION TrapInfo {
public:
    explicit TrapInfo(trap_pointer_t trap_data, size_t trap_size) {
        m_trap_data = trap_data;
        m_trap_size = trap_size;
        auto tmp_trap_ptr = m_trap_data;
        trap_read_header(&m_header, &tmp_trap_ptr, NULL, &m_header);
    }

    TrapIterator<trap_record_t> begin() const {
        return TrapIterator<trap_record_t>(&m_header, m_header.record_start, 0,
                                           trap_read_record);
    }

    TrapIterator<trap_record_t> end() const {
        return TrapIterator<trap_record_t>(&m_header, m_trap_data + m_trap_size, 0,
                                           trap_read_record);
    }

    const struct trap_header_t *header() const {
        return &m_header;
    }

    TrapRelocVector nonexec_relocations() const {
        RANDO_ASSERT(m_header.reloc_end != nullptr);
        // TODO: do we want to introduce a base address for these???
        // (so they don't start from zero)
        return TrapRelocVector(m_header.reloc_start, m_header.reloc_end, 0,
                               &m_header);
    }

private:
    trap_pointer_t m_trap_data;
    size_t m_trap_size;
    struct trap_header_t m_header;
};
#endif // __cplusplus

#pragma pop_macro("SET_FIELD")
#pragma pop_macro("SCAST")
#pragma pop_macro("RCAST")

#endif // __RANDOLIB_TRAPINFO_H
