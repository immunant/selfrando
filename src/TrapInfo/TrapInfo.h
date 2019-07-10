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

#ifndef __RANDOLIB_TRAPINFO_H
#define __RANDOLIB_TRAPINFO_H
#pragma once

#include <TrapPlatform.h>
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

#ifdef _MSC_VER
#include <intrin.h>

/*
* We have a problem with uint64_t on Win32 MSVC:
* MSVC compiles the left-shift of a uint64_t to
* a function call to __allshl, which is usually inside
* the main binary and therefore at a randomized location.
* We need to avoid all direct left shifts, and use our
* own function.
*/
static inline RANDO_SECTION
uint64_t __TRaP_shl_uint64(uint64_t val, size_t bits) {
#if defined(_WIN64)
    return val << bits;
#else // _WIN64
    if (bits >= 64)
        return 0ULL;
    if (bits >= 32) {
        union {
            uint32_t a[2];
            uint64_t b;
        } u;
        u.a[0] = 0;
        u.a[1] = SCAST(uint32_t, val) << (bits - 32);
        return u.b;
    }
    return __ll_lshift(val, bits);
#endif
}
#else // _MSC_VER
static inline RANDO_SECTION
uint64_t __TRaP_shl_uint64(uint64_t val, size_t bits) {
    return val << bits;
}
#endif

struct trap_header_t;

typedef uint8_t *trap_pointer_t;
typedef uint64_t trap_address_t;
typedef int (*trap_read_func_t)(const struct trap_header_t*,
                                trap_pointer_t*,
                                trap_address_t*,
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
    uint64_t res = 0;
    size_t shift = 0;
    while (((**trap_ptr) & 0x80) != 0) {
        res += __TRaP_shl_uint64(**trap_ptr & 0x7F, shift);
        shift += 7;
        (*trap_ptr)++;
    }
    res += __TRaP_shl_uint64(**trap_ptr, shift);
    (*trap_ptr)++;
    return res;
}

static inline RANDO_SECTION
int64_t trap_read_sleb128(trap_pointer_t *trap_ptr) {
    int64_t res = 0, sign_bit;
    size_t shift = 0;
    while (((**trap_ptr) & 0x80) != 0) {
        res += SCAST(int64_t, __TRaP_shl_uint64(**trap_ptr & 0x7F, shift));
        shift += 7;
        (*trap_ptr)++;
    }
    res += SCAST(int64_t, __TRaP_shl_uint64(**trap_ptr, shift));
    (*trap_ptr)++;
    shift += 7;

    sign_bit = SCAST(int64_t, __TRaP_shl_uint64(1, shift - 1));
    if ((res & sign_bit) != 0)
        res |= -SCAST(int64_t, __TRaP_shl_uint64(1, shift));
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
    TRAP_BASE_RELATIVE_ADDRESSES = 0x40000,
} trap_header_flags_t;

// Warning: relies on little-endianness
#pragma pack(push, 1)
struct RANDO_SECTION trap_header_t {
    union {
        uint8_t version;
        uint32_t flags;
    };
    uint64_t pointer_size;

    // Start of internal fields.
    // Everything up to this point is read from the TRaP data.
    // Fields starting from here are our own.
    trap_pointer_t reloc_start, reloc_end;
    trap_pointer_t record_start;

    // Host platform
    trap_platform_t platform;

    // Base address to add to all addresses encoded in TRaP info.
    trap_address_t base_address;

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

    bool has_pointer_size() const {
        return (flags & TRAP_HAS_POINTER_SIZE) != 0;
    }

    bool base_relative_addresses() const {
        return (flags & TRAP_BASE_RELATIVE_ADDRESSES) != 0;
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
trap_address_t trap_read_address(const struct trap_header_t *header,
                                 trap_pointer_t *trap_ptr) {
    trap_address_t addr;
    if (trap_header_has_flag(header, TRAP_PC_RELATIVE_ADDRESSES) ||
        trap_header_has_flag(header, TRAP_BASE_RELATIVE_ADDRESSES)) {
        if (trap_header_has_flag(header, TRAP_BASE_RELATIVE_ADDRESSES)) {
            addr = header->base_address;
        } else {
            addr = RCAST(trap_address_t, *trap_ptr);
        }
        if (header->pointer_size == 32) {
            int64_t delta = SCAST(int64_t, *RCAST(int32_t*, *trap_ptr));
            *trap_ptr += sizeof(int32_t);
            // Truncate the result to 32 bits, since the addition may overflow
            addr = (addr + delta) & 0xffffffffULL;
        } else {
            int64_t delta = *RCAST(int64_t*, *trap_ptr);
            *trap_ptr += sizeof(int64_t);
            addr += delta;
        }
    } else {
        if (header->pointer_size == 32) {
            addr = SCAST(trap_address_t, *RCAST(uint32_t*, *trap_ptr));
            *trap_ptr += sizeof(uint32_t);
        } else {
            addr = SCAST(trap_address_t, *RCAST(uint64_t*, *trap_ptr));
            *trap_ptr += sizeof(uint64_t);
        }
    }
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
    trap_address_t address = 0;
    int cont = 0;
    do {
        cont = (*read_func)(trap_header, trap_ptr, &address, NULL);
    } while (cont);
}

#pragma pack(push, 1)
struct RANDO_SECTION trap_reloc_t {
    trap_address_t address;
    uint64_t type;
    // FIXME: figure out a way to not store these in memory
    // when they're not needed
    trap_address_t symbol;
    int64_t addend;
};
#pragma pack(pop)

static inline RANDO_SECTION
int trap_read_reloc(const struct trap_header_t *header,
                    trap_pointer_t *trap_ptr,
                    trap_address_t *address,
                    void *data) {
    struct trap_reloc_t *reloc = RCAST(struct trap_reloc_t*, data);
    uint64_t curr_delta = trap_read_uleb128(trap_ptr);
    uint64_t curr_type = trap_read_uleb128(trap_ptr);
    int end = (curr_delta == 0 && curr_type == 0);

    uint64_t extra_info = trap_reloc_info(curr_type, header->platform);
    trap_address_t curr_symbol = 0;
    int64_t curr_addend = 0;
    if (!end) {
        if ((extra_info & TRAP_RELOC_SYMBOL) != 0)
            curr_symbol = trap_read_address(header, trap_ptr);
        if ((extra_info & TRAP_RELOC_ADDEND) != 0)
            curr_addend = trap_read_sleb128(trap_ptr);
        if ((extra_info & TRAP_RELOC_ARM64_GOT_PAGE) != 0) {
            // HACK: store the ARM64 instruction in curr_symbol,
            // since we should never have both TRAP_RELOC_SYMBOL
            // along with this one
            curr_symbol = SCAST(trap_address_t, *RCAST(uint32_t*, *trap_ptr));
            *trap_ptr += sizeof(uint32_t);
        }
        if ((extra_info & TRAP_RELOC_ARM64_GOT_GROUP) != 0) {
            // 3x bigger HACK: we have 3 32-bit values, so we store the first
            // one in curr_symbol and the other 2 inside addend
            curr_symbol = SCAST(trap_address_t, *RCAST(uint32_t*, *trap_ptr));
            *trap_ptr += sizeof(uint32_t);
            curr_addend = SCAST(int64_t, *RCAST(uint32_t*, *trap_ptr));
            *trap_ptr += sizeof(uint32_t);
            curr_addend |= SCAST(int64_t, *RCAST(uint32_t*, *trap_ptr)) << 32;
            *trap_ptr += sizeof(uint32_t);
        }
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
    trap_address_t address;
    uint64_t p2align;
    uint64_t size;
};
#pragma pack(pop)

static inline RANDO_SECTION
int trap_read_symbol(const struct trap_header_t *header,
                     trap_pointer_t *trap_ptr,
                     trap_address_t *address,
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

    *address += curr_delta;
    SET_FIELD(symbol, address, *address);
    SET_FIELD(symbol, p2align, curr_p2align);
    SET_FIELD(symbol, size,    curr_size);
    return !(curr_delta == 0 && curr_size == 0 && curr_p2align == 0);
}

static inline RANDO_SECTION
int trap_read_header(struct trap_header_t *header,
                     trap_pointer_t *trap_ptr,
                     trap_platform_t platform,
                     trap_address_t base_address) {
    uint32_t flags = *RCAST(uint32_t*, *trap_ptr);
    SET_FIELD(header, flags, flags);
    *trap_ptr += sizeof(uint32_t);

    SET_FIELD(header, platform, platform);
    SET_FIELD(header, base_address, base_address);

    SET_FIELD(header, reloc_start, *trap_ptr);
    if (flags & TRAP_HAS_NONEXEC_RELOCS) {
        trap_skip_vector(header, trap_ptr, trap_read_reloc);
        SET_FIELD(header, reloc_end, (*trap_ptr - 2));
    } else {
        SET_FIELD(header, reloc_end, *trap_ptr);
    }
    if (flags & TRAP_HAS_POINTER_SIZE) {
        uint64_t pointer_size = trap_read_uleb128(trap_ptr);
        SET_FIELD(header, pointer_size, pointer_size);
    } else {
        // If we don't have the pointer size in TRaP info,
        // get it from the platform info
        SET_FIELD(header, pointer_size,
                  trap_platform_pointer_size(platform));
    }
    SET_FIELD(header, record_start, *trap_ptr);
    return 1;
}

#ifdef __cplusplus
template<typename DataType>
class RANDO_SECTION TrapIterator {
public:
    explicit TrapIterator(const struct trap_header_t *header,
                          trap_pointer_t trap_ptr,
                          trap_address_t address,
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
    trap_address_t m_address;
    const trap_read_func_t m_func;
};

class RANDO_SECTION TrapVector {
public:
    TrapVector(const struct trap_header_t *header, trap_pointer_t start,
               trap_pointer_t end, trap_address_t address)
        : m_header(header), m_start(start),
          m_end(end), m_address(address) {}

private:
    // Reader function to pass to TrapIterator
    static int read_element(const struct trap_header_t *header,
                            trap_pointer_t *trap_ptr,
                            trap_address_t *address,
                            void *data) {
        (void) header; // Eliminate unused warning
        auto delta = trap_read_uleb128(trap_ptr);
        *address += delta;
        if (data)
            *RCAST(trap_address_t*, data) = *address;
        return 1;
    }

public:
    TrapIterator<trap_address_t> begin() {
        return TrapIterator<trap_address_t>(m_header, m_start, m_address,
                                            read_element);
    }

    TrapIterator<trap_address_t> end() {
        RANDO_ASSERT(m_end[0] == 0 || m_start == m_end);
        // FIXME: use MAX_INT instead of 0???
        return TrapIterator<trap_address_t>(m_header, m_end, 0,
                                            read_element);
    }

private:
    const struct trap_header_t *m_header;
    trap_pointer_t m_start, m_end;
    trap_address_t m_address;
};

class RANDO_SECTION TrapRelocVector {
public:
    TrapRelocVector() = delete;
    TrapRelocVector(trap_pointer_t start, trap_pointer_t end,
                    trap_address_t address, const struct trap_header_t *header)
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
    trap_address_t m_address;
    const struct trap_header_t *m_header;
};

// TODO: maybe we can merge this with TrapVector (using templates???)
class RANDO_SECTION TrapSymbolVector {
public:
    TrapSymbolVector(const struct trap_header_t *header,
                     trap_pointer_t start,
                     trap_pointer_t end,
                     trap_address_t address)
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
    trap_address_t m_address;
};
#endif // __cplusplus

#pragma pack(push, 1)
struct RANDO_SECTION trap_record_t {
    const struct trap_header_t *header; // TODO: get rid of this
    trap_address_t address;
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

    trap_address_t padding_address() {
        return address + padding_ofs;
    }
#endif // __cplusplus
};
#pragma pack(pop)

static inline RANDO_SECTION
int trap_read_record(const struct trap_header_t *header,
                     trap_pointer_t *trap_ptr,
                     trap_address_t *address,
                     void *data) {
    struct trap_record_t *record = RCAST(struct trap_record_t*, data);
    trap_address_t tmp_address = 0;
    trap_address_t record_address = trap_read_address(header, trap_ptr);
    SET_FIELD(record, header, header);
    SET_FIELD(record, address, record_address);
    // Parse symbol vector
    SET_FIELD(record, symbol_start, *trap_ptr);
    // We include the first symbol in the symbol vector
    // and we set m_address to the section address
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
    explicit TrapInfo(trap_pointer_t trap_data, size_t trap_size,
                      trap_platform_t platform,
                      trap_address_t base_address = 0) {
        m_trap_data = trap_data;
        m_trap_size = trap_size;
        auto tmp_trap_ptr = m_trap_data;
        trap_read_header(&m_header, &tmp_trap_ptr, platform, base_address);
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

    template<typename Func>
    void for_all_relocations(Func func) const {
        if (m_header.has_nonexec_relocs()) {
            trap_reloc_t trap_reloc;
            trap_pointer_t reloc_trap_ptr = m_header.reloc_start;
            trap_address_t reloc_address = 0;
            while (reloc_trap_ptr < m_header.reloc_end &&
                   trap_read_reloc(&m_header, &reloc_trap_ptr,
                                   &reloc_address, &trap_reloc))
                func(trap_reloc);
        }

        trap_record_t record;
        trap_pointer_t trap_ptr = m_header.record_start;
        trap_address_t address = 0;
        while (trap_ptr < m_trap_data + m_trap_size &&
               trap_read_record(&m_header, &trap_ptr,
                                &address, &record)) {
            trap_reloc_t trap_reloc;
            trap_pointer_t reloc_trap_ptr = record.reloc_start;
            trap_address_t reloc_address = record.address;
            while (reloc_trap_ptr < record.reloc_end &&
                   trap_read_reloc(&m_header, &reloc_trap_ptr,
                                   &reloc_address, &trap_reloc))
                func(trap_reloc);
        }
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
