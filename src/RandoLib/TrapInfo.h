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

#include <OS.h>
#include <TrapInfoCommon.h>

#include <utility>

// FIXME: is uintptr_t the correct type here?
static inline RANDO_SECTION uintptr_t ReadULEB128(os::BytePointer *trap_ptr) {
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

static inline RANDO_SECTION ptrdiff_t ReadSLEB128(os::BytePointer *trap_ptr) {
    ptrdiff_t res = 0, shift = 0;
    while (((**trap_ptr) & 0x80) != 0) {
        res += ((**trap_ptr) & 0x7F) << shift;
        shift += 7;
        (*trap_ptr)++;
    }
    res += (**trap_ptr) << shift;
    (*trap_ptr)++;
    shift += 7;

    ptrdiff_t sign_bit = static_cast<ptrdiff_t>(1) << (shift - 1);
    if ((res & sign_bit) != 0)
        res |= -(static_cast<ptrdiff_t>(1) << shift);
    return res;
}

// Warning: relies on little-endianness
union RANDO_SECTION TrapHeader {
public:
    uint8_t version;
    uint32_t flags;
    // TODO: Extend this structure to contain non-exec relocs vector

    enum Flags : uint32_t {
        FUNCTIONS_MARKED = 0x100,
        PRE_SORTED = 0x200,
        HAS_SYMBOL_SIZE = 0x400,
        HAS_DATA_REFS = 0x800,
        HAS_RECORD_RELOCS = 0x1000,
        HAS_NONEXEC_RELOCS = 0x2000,
        HAS_RECORD_PADDING = 0x4000,
        PC_RELATIVE_ADDRESSES = 0x8000,
        HAS_SYMBOL_P2ALIGN = 0x10000,
    };

    // Do the Trap records also contain size info???
    bool has_symbol_size() const {
        return (flags & Flags::HAS_SYMBOL_SIZE) != 0;
    }

    bool has_data_refs() const {
        return (flags & Flags::HAS_DATA_REFS) != 0;
    }

    // Return false if the Trap records are already sorted
    bool needs_sort() const {
        return (flags & Flags::PRE_SORTED) == 0;
    }

    bool has_record_relocs() const {
        return (flags & Flags::HAS_RECORD_RELOCS) != 0;
    }

    bool has_nonexec_relocs() const {
        return (flags & Flags::HAS_NONEXEC_RELOCS) != 0;
    }

    bool has_record_padding() const {
        return (flags & Flags::HAS_RECORD_PADDING) != 0;
    }

    bool pc_relative_addresses() const {
        return (flags & Flags::PC_RELATIVE_ADDRESSES) != 0;
    }

    bool has_symbol_p2align() const {
        return (flags & Flags::HAS_SYMBOL_P2ALIGN) != 0;
    }

    size_t elements_in_symbol() const {
        size_t elems = 1;
        if (has_symbol_p2align())
            elems++;
        if (has_symbol_size())
            elems++;
        return elems;
    }
};
static_assert(sizeof(TrapHeader) == 4, "Invalid size of Header structure");

static inline RANDO_SECTION void SkipTrapVector(os::BytePointer *trap_ptr) {
    while (**trap_ptr)
        (*trap_ptr)++;
    (*trap_ptr)++;
}

static inline RANDO_SECTION void SkipTrapSymbolVector(os::BytePointer *trap_ptr,
                                                      const TrapHeader *header) {
    // TrapSymbolVector ends in N consecutive zeroes,
    // where N is the number of elements in a TrapSymbol
    for (;;) {
        size_t left = header->elements_in_symbol();
        while (left > 0 && !**trap_ptr) {
            left--;
            (*trap_ptr)++;
        }
        if (left == 0)
            return;
        (*trap_ptr)++;
    }
}

static inline RANDO_SECTION void SkipTrapRelocVector(os::BytePointer *trap_ptr,
                                                     const TrapHeader *trap_header) {
    for (;;) {
        auto curr_delta = ReadULEB128(trap_ptr);
        auto curr_type  = ReadULEB128(trap_ptr);
        if (curr_delta == 0 && curr_type == 0)
            break;

        auto extra_info = RelocExtraInfo(curr_type);
        if ((extra_info & EXTRA_SYMBOL) != 0)
            *trap_ptr += trap_header->pc_relative_addresses()
                         ? sizeof(ptrdiff_t) : sizeof(uintptr_t);
        // TODO: we currently encode the addend as a native "ptrdiff" type,
        // which is pretty wasteful; we should use a SLEB128 instead
        // but first we need to implement support for SLEB128s
        if ((extra_info & EXTRA_ADDEND) != 0)
            ReadSLEB128(trap_ptr);
    }
}

class RANDO_SECTION TrapVector {
public:
    TrapVector(os::BytePointer start, os::BytePointer end, uintptr_t address)
        : m_start(start), m_end(end), m_address(address) {}

    class Iterator {
    public:
        explicit Iterator(os::BytePointer trap_ptr, uintptr_t address)
            : m_trap_ptr(trap_ptr), m_address(address) {}
        Iterator(const Iterator&) = default;
        Iterator &operator=(const Iterator&) = default;

        // Preincrement
        Iterator &operator++() {
            auto delta = ReadULEB128(&m_trap_ptr);
            m_address += delta;
            return *this;
        }

        // FIXME: better return type
        uintptr_t operator*() const {
            // FIXME: would be faster to add curr_delta to m_address in advance
            // so this turns into a simple read from m_address
            auto tmp_trap_ptr = m_trap_ptr;
            auto curr_delta = ReadULEB128(&tmp_trap_ptr);
            return m_address + curr_delta;
        }

        bool operator==(const Iterator &it) const {
            return m_trap_ptr == it.m_trap_ptr;
        }

        bool operator!=(const Iterator &it) const {
            return m_trap_ptr != it.m_trap_ptr;
        }

    private:
        os::BytePointer m_trap_ptr;
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
    os::BytePointer m_start, m_end;
    uintptr_t m_address;
};

struct RANDO_SECTION TrapReloc {
    uintptr_t address;
    size_t type;
    // FIXME: figure out a way to not store these in memory
    // when they're not needed
    uintptr_t symbol;
    ptrdiff_t addend;

    TrapReloc() = delete;
    TrapReloc(uintptr_t address, size_t type, uintptr_t symbol = 0, ptrdiff_t addend = 0)
        : address(address), type(type), symbol(symbol), addend(addend) { }
};

struct RANDO_SECTION TrapRelocVector {
public:
    TrapRelocVector() = delete;
    TrapRelocVector(os::BytePointer start, os::BytePointer end,
                    uintptr_t address, const TrapHeader *header)
        : m_start(start), m_end(end), m_address(address), m_header(header) {}

    class Iterator {
    public:
        explicit Iterator(os::BytePointer trap_ptr, uintptr_t address,
                          const TrapHeader *header)
            : m_trap_ptr(trap_ptr), m_address(address), m_header(header) {}
        Iterator(const Iterator&) = default;
        Iterator &operator=(const Iterator&) = default;

        // Preincrement
        Iterator &operator++() {
            auto delta = ReadULEB128(&m_trap_ptr);
            auto  type = static_cast<size_t>(ReadULEB128(&m_trap_ptr));
            m_address += delta;

            auto extra_info = RelocExtraInfo(type);
            if ((extra_info & EXTRA_SYMBOL) != 0)
                m_trap_ptr += m_header->pc_relative_addresses()
                              ? sizeof(ptrdiff_t) : sizeof(uintptr_t);
            if ((extra_info & EXTRA_ADDEND) != 0)
                ReadSLEB128(&m_trap_ptr);
            return *this;
        }

        const TrapReloc operator*() const {
            auto tmp_trap_ptr = m_trap_ptr;
            auto curr_delta = ReadULEB128(&tmp_trap_ptr);
            auto curr_type = static_cast<size_t>(ReadULEB128(&tmp_trap_ptr));

            auto extra_info = RelocExtraInfo(curr_type);
            uintptr_t curr_symbol = 0;
            ptrdiff_t curr_addend = 0;
            if ((extra_info & EXTRA_SYMBOL) != 0) {
                if (m_header->pc_relative_addresses()) {
                    auto delta = *reinterpret_cast<ptrdiff_t*>(tmp_trap_ptr);
#if !RANDOLIB_IS_ARM64
                    // We use GOT-relative offsets
                    // We add the GOT base later inside of Address::to_ptr()
                    curr_symbol = static_cast<uintptr_t>(delta);
#else
                    curr_symbol = reinterpret_cast<uintptr_t>(tmp_trap_ptr + delta);
#endif
                    tmp_trap_ptr += sizeof(ptrdiff_t);
                } else {
                    curr_symbol = *reinterpret_cast<uintptr_t*>(tmp_trap_ptr);
                    tmp_trap_ptr += sizeof(uintptr_t);
                }
            }
            if ((extra_info & EXTRA_ADDEND) != 0)
                curr_addend = ReadSLEB128(&tmp_trap_ptr);
            return TrapReloc(m_address + curr_delta, curr_type,
                             curr_symbol, curr_addend);
        }

        bool operator==(const Iterator &it) const {
            return m_trap_ptr == it.m_trap_ptr;
        }

        bool operator!=(const Iterator &it) const {
            return m_trap_ptr != it.m_trap_ptr;
        }

    private:
        os::BytePointer m_trap_ptr;
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
    os::BytePointer m_start, m_end;
    uintptr_t m_address;
    const TrapHeader *m_header;
};

struct RANDO_SECTION TrapAddnHeaderInfo {
private:
    os::BytePointer reloc_start, reloc_end = nullptr;
    const TrapHeader *header_start_ptr;
    os::BytePointer header_end_ptr = nullptr;

public:
    TrapAddnHeaderInfo() {} // Invalid struct constructor

    TrapAddnHeaderInfo(const TrapHeader* header) {
        header_start_ptr = header;
        auto curr_ptr = reinterpret_cast<os::BytePointer>(const_cast<TrapHeader*>(header + 1));
        reloc_start = reloc_end = curr_ptr;
        if (header->has_nonexec_relocs()) {
            SkipTrapRelocVector(&curr_ptr, header);
            reloc_end = curr_ptr - 2;
        }
        header_end_ptr = curr_ptr;
    }

    os::BytePointer header_end() const {
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

#pragma pack(1)
struct RANDO_SECTION TrapSymbol {
    uintptr_t address;
    uintptr_t alignment;
    size_t size;

    TrapSymbol(uintptr_t addr, uintptr_t align, size_t sz = 0)
        : address(addr), alignment(align), size(sz) {}

    void dump() const {
        os::API::DebugPrintf<4>("Sym: %p [%u]\n", address, size);
    }
};

// TODO: maybe we can merge this with TrapVector (using templates???)
class RANDO_SECTION TrapSymbolVector {
public:
    TrapSymbolVector(const TrapHeader *header, os::BytePointer start, os::BytePointer end, uintptr_t address)
        : m_header(header), m_start(start), m_end(end), m_address(address) {}

    class Iterator {
    public:
        explicit Iterator(const TrapHeader *header, os::BytePointer trap_ptr, uintptr_t address)
            : m_header(header), m_trap_ptr(trap_ptr), m_address(address) {}
        Iterator(const Iterator&) = default;
        Iterator &operator=(const Iterator&) = default;

        // Preincrement
        Iterator &operator++() {
            auto delta = ReadULEB128(&m_trap_ptr);
            m_address += delta;
            if (m_header->has_symbol_p2align())
                ReadULEB128(&m_trap_ptr);
            if (m_header->has_symbol_size()) {
                auto size = ReadULEB128(&m_trap_ptr);
                m_address += size;
            }
            return *this;
        }

        TrapSymbol operator*() const {
            // FIXME: would be faster to add curr_delta to m_address in advance
            // so this turns into a simple read from m_address
            auto tmp_trap_ptr = m_trap_ptr;
            auto curr_delta = ReadULEB128(&tmp_trap_ptr);
            uintptr_t alignment = 1;
            if (m_header->has_symbol_p2align())
                alignment = 1 << ReadULEB128(&tmp_trap_ptr);
            if (m_header->has_symbol_size()) {
                auto size = ReadULEB128(&tmp_trap_ptr);
                return TrapSymbol(m_address + curr_delta, alignment, size);
            }
            return TrapSymbol(m_address + curr_delta, alignment);
        }

        bool operator==(const Iterator &it) const {
            return m_trap_ptr == it.m_trap_ptr;
        }

        bool operator!=(const Iterator &it) const {
            return m_trap_ptr != it.m_trap_ptr;
        }

    private:
        const TrapHeader *m_header;
        os::BytePointer m_trap_ptr;
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
    os::BytePointer m_start, m_end;
    uintptr_t m_address;
};

class RANDO_SECTION TrapRecord {
public:
    TrapRecord(const TrapHeader *header, os::BytePointer record_start, os::BytePointer record_end)
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
        auto first_sym_ofs = ReadULEB128(&trap_ptr);
        m_address -= first_sym_ofs;
        if (header->has_symbol_p2align())
            ReadULEB128(&trap_ptr);
        if (header->has_symbol_size())
            ReadULEB128(&trap_ptr);
        SkipTrapSymbolVector(&trap_ptr, header);
        m_symbol_end = trap_ptr - header->elements_in_symbol();
        // Relocations vector
        m_reloc_start = m_reloc_end = trap_ptr;
        if (header->has_record_relocs()) {
            SkipTrapRelocVector(&trap_ptr, header);
            m_reloc_end = trap_ptr - 2;
        }
        // Data references
        m_data_refs_start = m_data_refs_end = trap_ptr;
        if (header->has_data_refs()) {
            SkipTrapVector(&trap_ptr);
            m_data_refs_end = trap_ptr - 1;
        }
        if (header->has_record_padding()) {
            m_padding_ofs = ReadULEB128(&trap_ptr);
            m_padding_size = ReadULEB128(&trap_ptr);
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

    void dump() {
        os::API::DebugPrintf<4>("Trap record @ %p:\n", m_start);
        os::API::DebugPrintf<4>("  symbols\n");
        for (auto sym : symbols())
            os::API::DebugPrintf<4>("    Sym: %p [%u]\n",
                                    sym.address,
                                    sym.size);

        os::API::DebugPrintf<4>("  relocations\n");
        for (auto reloc : relocations())
            os::API::DebugPrintf<4>("    Reloc %u: %p = %p+%d\n",
                                    reloc.type, reloc.address, reloc.symbol,
                                    reloc.addend);

        if (m_header->has_data_refs()) {
            os::API::DebugPrintf<4>("  data refs\n");
            for (auto address : data_refs())
                os::API::DebugPrintf<4>("    address: %p\n", address);
        }
        if (m_header->has_record_padding()) {
            os::API::DebugPrintf<4>("  padding: %p[%u]\n", padding_address(), padding_size());
        }
    }

private:
    const TrapHeader *m_header;
    os::BytePointer m_start, m_end;
    uintptr_t m_address, m_first_sym_ofs, m_padding_ofs;
    size_t m_padding_size;
    os::BytePointer m_symbol_start, m_symbol_end;
    os::BytePointer m_reloc_start, m_reloc_end;
    os::BytePointer m_data_refs_start, m_data_refs_end;
};

class RANDO_SECTION TrapInfo {
public:
    explicit TrapInfo(os::BytePointer trap_data, size_t trap_size) {
        m_trap_data = trap_data;
        m_trap_size = trap_size;
        ReadHeader();
    }

    class Iterator {
    public:
        Iterator(const TrapHeader *header, os::BytePointer trap_ptr, bool end)
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
        os::BytePointer m_trap_ptr, m_trap_next;
        bool m_end;

        void AdvanceNext() {
            m_trap_next = m_trap_ptr;
            if (!m_end) {
                m_trap_next += m_header->pc_relative_addresses()
                               ? sizeof(ptrdiff_t) : sizeof(uintptr_t);
                ReadULEB128(&m_trap_next);
                if (m_header->has_symbol_p2align())
                    ReadULEB128(&m_trap_next);
                if (m_header->has_symbol_size())
                    ReadULEB128(&m_trap_next);
                SkipTrapSymbolVector(&m_trap_next, m_header);
                if (m_header->has_record_relocs())
                    SkipTrapRelocVector(&m_trap_next, m_header);
                if (m_header->has_data_refs())
                    SkipTrapVector(&m_trap_next);
                if (m_header->has_record_padding()) {
                    ReadULEB128(&m_trap_next);
                    ReadULEB128(&m_trap_next);
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
    os::BytePointer m_trap_data, m_trap_records;
    size_t m_trap_size;
    TrapHeader *m_header;
    TrapAddnHeaderInfo m_addn_info;

    void ReadHeader() {
        m_header = reinterpret_cast<TrapHeader*>(m_trap_data);
        m_addn_info = TrapAddnHeaderInfo(m_header);
        m_trap_records = m_addn_info.header_end();
        RANDO_ASSERT(m_trap_records <= (m_trap_data + m_trap_size));
        RANDO_ASSERT(m_header->version == 1);
    }
};

#endif // __RANDOLIB_TRAPINFO_H
