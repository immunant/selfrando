/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <Debug.h>

#include <libelf.h>
#include <gelf.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include <TrapInfo.h>

typedef int64_t Elf_Offset;
typedef size_t Elf_SectionIndex;

class ElfObject;
class ElfStringTable;
class ElfSymbolTable;
class ElfSymbolXindexTable;
class TrapRecordBuilder;
class ElfSymbolTable;

enum ObjectType {
    STATIC_OBJECT,
    LINKER_SCRIPT,
    SHARED_OBJECT,
    UNKNOWN,
};

ObjectType parse_object_type(int fd);

class ElfStringTable {
public:
    ElfStringTable() = delete;
    ElfStringTable(Elf_Scn *section);

    size_t add_string(const std::string &string) {
        return internal_add_string(std::string{string});
    }

    size_t add_string(const char *string) {
        return internal_add_string(std::string{string});
    }

    std::string get_string(size_t index) {
        // FIXME: this used to be constant-time, but is now logarithmic
        auto idx_it = std::prev(std::upper_bound(m_indices.begin(),
                                                 m_indices.end(),
                                                 index));
        auto idx_pos = std::distance(m_indices.begin(), idx_it);
        auto idx_ofs = index - m_indices[idx_pos];
        return std::string(m_string_table[idx_pos]->c_str() + idx_ofs);
    }

    void update(ElfObject &object);

private:
    using StringPtr = std::shared_ptr<const std::string>;

    size_t internal_add_string(std::string &&string) {
        // Not sure if std::move() is needed here,
        // but leaving it in just to be sure
        auto sp = std::make_shared<const std::string>(std::move(string));
        StringSuffix ss{sp, 0};
        auto it = m_string_index_map.find(ss);
        if (it != m_string_index_map.end())
            return it->second;

        auto idx = m_next_index;
        m_string_table.push_back(sp);
        m_indices.push_back(idx);
        // Advance the index, including the null terminator
        m_next_index += m_string_table.back()->size() + 1;

        // Add the string and all its suffixes to the hash map
        hash_string_suffixes(sp, idx);
        return idx;
    }

    void hash_string_suffixes(StringPtr sp, size_t idx) {
        // Add all suffixes of the last added string
        // to the hash map
        for (size_t i = 0; i < sp->size(); i++)
            if ((*sp)[i] != '\0') {
                StringSuffix ss{sp, i};
                m_string_index_map[ss] = idx + i;
            }
    }

    // Structure that efficiently stores the suffix of an existing string,
    // split into two components:
    // - a shared_ptr pointing to the underlying string
    // - a start position indicating where the suffix starts in the string
    struct StringSuffix {
        StringPtr s;
        size_t start;

        StringSuffix(StringPtr s, size_t start)
            : s(s), start(start) { }

        bool operator==(const StringSuffix &o) const {
            for (size_t i = 0;; i++) {
                bool end1 = (  start + i) >=   s->size();
                bool end2 = (o.start + i) >= o.s->size();
                if (end1 && end2)
                    return true;  // Reached the end of both strings at the same time
                if (end1 || end2)
                    return false; // Reached the end of one string, so they're not equal
                if ((*s)[start + i] != (*o.s)[o.start + i])
                    return false; // Mismatch
                if ((*s)[start + i] == '\0')
                    return true;  // Null terminator in both strings => match
            }
        }

        bool operator!=(const StringSuffix &o) const {
            return !(*this == o);
        }
    };

    // djb2 hash for char*'s for std::unordered_map
    struct StringSuffixHash {
        size_t operator() (const StringSuffix &ss) const {
            unsigned long hash = 5381;
            for (size_t i = ss.start; i < ss.s->size() && (*ss.s)[i] != '\0'; i++)
                hash = ((hash << 5) + hash) + static_cast<int>((*ss.s)[i]);
            return static_cast<size_t>(hash);
        }
    };

    Elf_Scn *m_section;
    std::vector<StringPtr> m_string_table;
    std::vector<size_t> m_indices;
    size_t m_initial_size;
    size_t m_next_index;
    std::unordered_map<StringSuffix, size_t, StringSuffixHash> m_string_index_map;
};

using ElfStringTablePtr = std::shared_ptr<ElfStringTable>;

class ElfSymbolTable {
public:
    ElfSymbolTable(Elf *elf, ElfObject &object);

    void finalize();

    size_t section_index() {
        return elf_ndxscn(m_section);
    }

    bool empty() const {
        if (m_section == nullptr)
            return true;
        if (m_input_locals.empty() && m_input_globals.empty())
            return true;
        return false;
    }

    const ElfObject *object() const {
        return &m_object;
    }

public:
    class XindexTable {
    public:
        XindexTable(ElfObject &object);

        uint32_t get(size_t idx) const {
            return m_xindex_table[idx];
        }

        void set(size_t idx, uint32_t shndx) {
            m_xindex_table[idx] = shndx;
        }

        uint32_t translate_shndx(size_t idx, uint16_t shndx) const {
            if (shndx == SHN_XINDEX)
                return m_xindex_table[idx];
            return shndx;
        }

        void resize(size_t new_size) {
            if (new_size > m_xindex_table.size())
                m_xindex_table.resize(new_size);
        }

        void add_new(size_t where, const std::vector<uint32_t> &new_entries);

        void update();

    private:
        ElfObject &m_object;

        Elf_Scn *m_section;

        uint32_t m_symtab_index;

        std::vector<uint32_t> m_xindex_table;
    };

    XindexTable &xindex_table() {
        return m_xindex_table;
    }

public:
    class SymbolRef {
    public:
        SymbolRef() : m_symtab(nullptr), m_source(NONE), m_index(0) {
        }

        bool is_valid() const {
            return m_symtab != nullptr && m_source != NONE;
        }

        size_t get_input_index() const {
            size_t base = 0;
            switch (m_source) {
            case INPUT_GLOBAL:
                base += m_symtab->m_input_locals.size();
                // Fall-through
            case INPUT_LOCAL:
                return base + m_index;
            default:
                assert(false && "Unknown SymbolRef source");
                return 0;
            }
        }

        size_t get_final_index() const {
            assert(m_symtab->m_finalized &&
                   "Attempted to get address of non-finalized symbol");
            size_t base = 0;
            switch (m_source) {
            case NEW_GLOBAL:
                base += m_symtab->m_input_globals.size();
                // Fall-through
            case INPUT_GLOBAL:
                base += m_symtab->m_new_locals.size();
                // Fall-through
            case NEW_LOCAL:
                base += m_symtab->m_input_locals.size();
                // Fall-through
            case INPUT_LOCAL:
                return base + m_index;
            default:
                assert(false && "Unknown SymbolRef source");
                return 0;
            }
        }

        GElf_Sym *get() const {
            switch (m_source) {
            case INPUT_LOCAL:
                return &m_symtab->m_input_locals[m_index];
            case NEW_LOCAL:
                return &m_symtab->m_new_locals[m_index];
            case INPUT_GLOBAL:
                return &m_symtab->m_input_globals[m_index];
            case NEW_GLOBAL:
                return &m_symtab->m_new_globals[m_index];
            default:
                assert(false && "Invalid SymbolRef");
                return nullptr;
            }
        }

        // Get the section index of this symbol
        uint32_t get_shndx() const {
            auto *sym = get();
            if (sym->st_shndx != SHN_XINDEX)
                return sym->st_shndx;
            switch (m_source) {
            case INPUT_LOCAL:
            case INPUT_GLOBAL:
                return m_symtab->xindex_table().get(get_input_index());
            case NEW_LOCAL:
                return m_symtab->m_new_locals_xindex[m_index];
            case NEW_GLOBAL:
                return m_symtab->m_new_globals_xindex[m_index];
            default:
                assert(false && "Invalid SymbolRef");
                return 0;
            }
        }

        bool operator <(const SymbolRef &other) const {
            if (m_source == other.m_source)
                return m_index < other.m_index;
            return m_source < other.m_source;
        }

        // Get a local version of this symbol
        SymbolRef as_local() const {
            if (m_source == INPUT_LOCAL ||
                m_source == NEW_LOCAL)
                return *this;

            auto *glob_sym = get();
            if (glob_sym->st_shndx == SHN_UNDEF ||
                glob_sym->st_shndx == SHN_ABS ||
                glob_sym->st_shndx == SHN_COMMON)
                return *this; // This symbol is not in this file

            auto it = m_symtab->m_converted_globals.find(*this);
            if (it != m_symtab->m_converted_globals.end())
                return it->second;

            auto glob_shndx = get_shndx();
            auto local_name = m_symtab->get_suffixed_symbol(glob_sym->st_name, "$local");
            auto local_sym = m_symtab->add_local_symbol(glob_sym->st_value, glob_shndx,
                                                        local_name, GELF_ST_TYPE(glob_sym->st_info),
                                                        glob_sym->st_size);
            m_symtab->m_converted_globals.emplace(*this, local_sym);
            return local_sym;
        }

    private:
        enum Source {
            NONE,
            INPUT_LOCAL,
            NEW_LOCAL,
            INPUT_GLOBAL,
            NEW_GLOBAL,
        };

        SymbolRef(ElfSymbolTable *symtab, Source source, size_t index)
           : m_symtab(symtab), m_source(source), m_index(index) {
        }

    private:
        ElfSymbolTable *m_symtab;
        Source m_source;
        size_t m_index;

        friend class ElfSymbolTable;
    };

    typedef std::map<SymbolRef, SymbolRef> SymbolMapping;

    SymbolRef get_input_symbol_ref(size_t idx) {
        if (idx >= m_input_locals.size())
            return SymbolRef(this, SymbolRef::INPUT_GLOBAL,
                             idx - m_input_locals.size());
        return SymbolRef(this, SymbolRef::INPUT_LOCAL, idx);
    }

    SymbolRef replace_symbol(SymbolRef symbol, GElf_Addr new_value,
                             Elf_SectionIndex section_index,
                             size_t new_size);

    void mark_entry_symbol(std::string symbol_name, std::string new_name);

    SymbolRef add_local_symbol(GElf_Addr address, Elf_SectionIndex section_index,
                               const std::string &name, uint8_t type,
                               size_t size = 0);

    SymbolRef add_section_symbol(Elf_SectionIndex section_index);

    std::string get_suffixed_symbol(size_t sym_index, const std::string &suffix) {
        std::string sym_name_suffix = m_string_table->get_string(sym_index);
        std::size_t pos = sym_name_suffix.find('@');
        // If the symbol is versioned, insert "$orig" before the at (@) char.
        if (pos != std::string::npos)
          sym_name_suffix.insert(pos, suffix);
        else
          sym_name_suffix += suffix;
        return sym_name_suffix;
    }

private:
    void find_symtab();
    void read_symbols();

    SymbolRef add_symbol(GElf_Sym symbol, uint32_t xindex);
    void update_symbol_references();

    void add_target_symbol(std::vector<uint8_t> *buf, const GElf_Sym &sym);

private:
    bool m_finalized;

    Elf_Scn *m_section;
    ElfObject &m_object;
    ElfStringTablePtr m_string_table;
    XindexTable m_xindex_table;

    std::vector<Elf_Scn*> m_rel_sections;
    std::vector<Elf_Scn*> m_rela_sections;

    std::vector<GElf_Sym> m_input_locals;
    std::vector<GElf_Sym> m_input_globals;
    std::vector<GElf_Sym> m_new_locals;
    std::vector<GElf_Sym> m_new_globals;
    std::vector<uint32_t> m_new_locals_xindex;
    std::vector<uint32_t> m_new_globals_xindex;

    // Map of globals converted to locals,
    // maintained by SymbolRef::as_local()
    SymbolMapping m_converted_globals;
};

#pragma pack(1)
struct TrapSymbol {
    Elf_Offset offset;
    ElfSymbolTable::SymbolRef symbol;
    Elf_Offset p2align;
    size_t size;

    TrapSymbol(Elf_Offset offset, ElfSymbolTable::SymbolRef symbol, Elf_Offset p2align,
               size_t size = 0)
        : offset(offset), symbol(symbol), p2align(p2align), size(size) {}

    bool operator <(const TrapSymbol &other) const {
        return offset < other.offset;
    }
};

struct ElfReloc {
    Elf_Offset offset;
    uint32_t type;
    // FIXME: figure out a way to not store these in memory
    // when they're not needed
    ElfSymbolTable::SymbolRef symbol;
    Elf_Offset addend;

    ElfReloc() = delete;
    ElfReloc(Elf_Offset offset, uint32_t type,
              ElfSymbolTable::SymbolRef symbol = ElfSymbolTable::SymbolRef(),
              Elf_Offset addend = 0)
        : offset(offset), type(type), symbol(symbol), addend(addend) { }

    bool operator <(const ElfReloc &other) const {
        return offset < other.offset;
    }
};

class ElfObject;
class TrampolineBuilder;

typedef std::vector<ElfReloc> Elf_RelocBuffer;

class TargetOps {
public:
    // Create an empty .rel.XXX section
    virtual Elf_SectionIndex
    create_reloc_section(ElfObject &object,
                         const std::string &section_name,
                         Elf_SectionIndex shndx,
                         Elf_SectionIndex symtab_shndx,
                         const Elf_RelocBuffer &relocs) = 0;

    // Adds a relocation to an Elf_RelocBuffer structure.
    // The caller should use whatever is left in reloc.addend
    // as the actual relocated data, in case the target arch
    // does not support explicit addends.
    virtual void
    add_reloc_to_buffer(Elf_RelocBuffer &buffer,
                        ElfReloc *reloc) = 0;

    // Copies an entire Elf_RelocBuffer to a section.
    virtual void
    add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                          const Elf_RelocBuffer &buffer) = 0;

    virtual bool
    check_rel_for_stubs(ElfObject &object, GElf_Rel *relocation, ptrdiff_t addend,
                        uint32_t shndx, TrapRecordBuilder &builder) = 0;

    virtual bool
    check_rela_for_stubs(ElfObject &object, GElf_Rela *relocation, ptrdiff_t addend,
                         uint32_t shndx, TrapRecordBuilder &builder) = 0;

    virtual Elf_Offset
    read_reloc(char* data, ElfReloc &reloc) = 0;

    virtual std::unique_ptr<TrampolineBuilder>
    get_trampoline_builder(ElfObject &object,
                           ElfSymbolTable &symbol_table) = 0;
};

class ElfObject {
public:
    ElfObject(std::pair<int, std::string> temp_file,
              std::pair<std::string, std::string> entry_points)
        : m_fd(temp_file.first), m_filename(temp_file.second),
          m_elf(nullptr), m_parsed(false),
          m_entry_points(entry_points) {
        m_elf = elf_begin(m_fd, ELF_C_RDWR, nullptr);
        get_elf_header();
    }

    ~ElfObject();

    bool needs_trap_info() const {
        return elf_kind(m_elf) != ELF_K_NONE
            && !is_shared();
    }

    size_t get_num_sections() const {
        return m_num_sections;
    }

    std::tuple<std::string, uint16_t> create_trap_info(bool emit_textramp,
                                                       bool emit_eh_txtrp,
                                                       const std::string &ar_path);

    void* data();

    struct DataBuffer {
        DataBuffer() : buffer(nullptr), size(0), align(1) {
        }

        DataBuffer(void* data, size_t size, unsigned align)
            : buffer(new char[size], std::default_delete<char[]>()),
              size(size), align(align) {
            memcpy(buffer.get(), data, size);
        };

        DataBuffer(std::pair<void*, size_t> buf_pair, unsigned align)
            : buffer(new char[buf_pair.second], std::default_delete<char[]>()),
              size(buf_pair.second), align(align) {
            memcpy(buffer.get(), buf_pair.first, buf_pair.second);
        };

        template<typename T>
        DataBuffer(std::vector<T> &buf, unsigned align)
            : buffer(new char[buf.size() * sizeof(T)], std::default_delete<char[]>()),
              size(buf.size() * sizeof(T)), align(align) {
            memcpy(buffer.get(), reinterpret_cast<char*>(buf.data()), size);
        }

        static DataBuffer get_empty_buffer() {
            return DataBuffer();
        }

        char* get() {
            return buffer.get();
        }

        std::shared_ptr<char> buffer;
        size_t size;
        unsigned align;
    };

    ElfStringTablePtr get_string_table(Elf_SectionIndex section_index);

    /// Returns the index of the new section
    unsigned add_section(std::string name,
                         GElf_Shdr *header,
                         DataBuffer buffer,
                         Elf_Type data_type = ELF_T_BYTE);

    bool add_int32_section_patch(uint32_t shndx, Elf_Offset offset,
                                 uint32_t mask, uint32_t value);

    // FIXME: we have two versions of this function: one that takes
    // a section index, and one that takes a section pointer.
    // We need both of them. However, elf_ndxscn is potentially slow,
    // so it might be worth optimizing these.
    Elf_Offset add_data(uint32_t shndx, void* data, size_t size, unsigned align = 1,
                       Elf_Type data_type = ELF_T_BYTE);

    Elf_Offset add_data(Elf_Scn *section, void* data, size_t size, unsigned align = 1,
                       Elf_Type data_type = ELF_T_BYTE) {
        return add_data(elf_ndxscn(section), data, size, align, data_type);
    }

    void replace_data(Elf_Scn *section, DataBuffer buffer);

    template<typename T>
    void add_section_relocs(Elf_SectionIndex section,
                            const T &relocs) {
        auto &rel_buf = m_section_relocs[section];
        rel_buf.insert(rel_buf.end(), relocs.begin(), relocs.end());
    }

    class Iterator {
    public:
        explicit Iterator(Elf *elf, bool end = false)
            : m_elf(elf), m_section(nullptr) {
            if (!end)
                next();
        }
        Iterator(const Iterator&) = default;
        Iterator &operator=(const Iterator&) = default;

        Iterator &operator++() {
            next();
            return *this;
        }

        Elf_Scn* operator*() const {
            return m_section;
        }

        Elf_Scn* operator->() const {
            return m_section;
        }

        bool operator==(const Iterator &it) const {
            return m_elf == it.m_elf
                && m_section == it.m_section;
        }

        bool operator !=(const Iterator &it) const {
            return m_elf != it.m_elf
                || m_section != it.m_section;
        }

    private:
        void next() {
            m_section = elf_nextscn(m_elf, m_section);
        }

        Elf *m_elf;
        Elf_Scn *m_section;
    };

    Iterator begin() {
        return Iterator(m_elf);
    }

    Iterator end() {
        return Iterator(m_elf, true);
    }

    bool is_shared() const {
        return elf_kind(m_elf) == ELF_K_ELF
            && m_ehdr.e_type == ET_DYN;
    }

    bool is_object() const {
        return elf_kind(m_elf) == ELF_K_ELF
            && m_ehdr.e_type == ET_REL;
    }

    bool is_archive() const {
        return elf_kind(m_elf) == ELF_K_AR;
    }

    struct TargetInfo {
        uint32_t none_reloc;
        uint32_t symbol_reloc;
        uint32_t copy_reloc;
        Elf_Offset min_p2align;
        Elf_Offset padding_p2align;
        size_t addr_size;
        trap_platform_t trap_platform;
        TargetOps *ops;
    };

    const TargetInfo *get_target_info() const {
        assert(m_target_info != nullptr);
        return m_target_info;
    }

public:
    static bool has_copy_relocs(const char *filename);

private:
    static const std::unordered_map<uint16_t, TargetInfo> kInfoForTargets;

    GElf_Ehdr* get_elf_header() {
        if (elf_kind(m_elf) != ELF_K_ELF)
            return nullptr;
        if (gelf_getehdr(m_elf, &m_ehdr) == nullptr) {
            std::cerr << "Could not get ELF header: " << elf_errmsg(-1) << '\n';
            return nullptr;
        }
        m_target_info = &kInfoForTargets.at(m_ehdr.e_machine);
        return &m_ehdr;
    }

    bool parse();

    std::string get_section_name(Elf_Scn *section) {
        assert(m_parsed);

        GElf_Shdr section_header;
        gelf_getshdr(section, &section_header);
        return m_section_header_strings->get_string(section_header.sh_name);
    }

    typedef std::map<uint32_t, TrapRecordBuilder> SectionBuilderMap;

    SectionBuilderMap create_section_builders(ElfSymbolTable *symbol_table);
    void prune_section_builders(SectionBuilderMap *section_builders,
                                bool emit_eh_txtrp);

    bool create_trap_info_impl(bool emit_textramp, bool emit_eh_txtrp);
    void add_anchor_reloc(const GElf_Shdr *header,
                          Elf_SectionIndex section_ndx,
                          Elf_SectionIndex symtab_section_ndx,
                          ElfSymbolTable::SymbolRef section_symbol,
                          size_t function_count);

    bool update_file();
    Elf* write_new_file(int fd);
    bool update_archive(const std::string &original_ar_path,
                        std::vector<std::string> object_files, std::string archive_filename);

    void add_shdr_strings(const std::vector<char> &str_table, size_t existing_count);

    bool needs_trampoline(GElf_Sym symbol) {
        // TODO: take linker options affecting visibility into account
        return (GELF_ST_BIND(symbol.st_info) != STB_LOCAL &&
                GELF_ST_VISIBILITY(symbol.st_other) != STV_HIDDEN);
    }

    /// File descriptor
    int m_fd;

    /// File name
    std::string m_filename;

    /// Current ELF object
    Elf *m_elf;

    /// Has parse() been called on this object?
    bool m_parsed;

    /// Current ELF header
    GElf_Ehdr m_ehdr;

    /// name of entry point symbol
    std::pair<std::string, std::string> m_entry_points;

    /// Fields used by parse()
    ElfStringTablePtr m_section_header_strings;

    /// Number of sections, including any pending new sections to be added
    size_t m_num_sections;

    std::list<DataBuffer> m_data_buffers;

    /// New sections to be added when we write this object back
    std::vector<std::pair<GElf_Shdr, DataBuffer> > m_new_sections;

    std::unordered_map<Elf_SectionIndex, Elf_Offset> m_section_sizes;

    std::map<Elf_SectionIndex, std::map<Elf_Offset, std::pair<uint32_t, uint32_t>>> m_section_patches;

    std::vector<DataBuffer> m_replacement_data;

    std::unordered_map<Elf_SectionIndex, ElfStringTablePtr> m_string_tables;

    std::map<Elf_SectionIndex, Elf_RelocBuffer> m_section_relocs;

    const TargetInfo *m_target_info;
};

typedef std::vector<ElfSymbolTable::SymbolRef> EntrySymbols;

class TrampolineBuilder {
public:
    TrampolineBuilder(ElfObject &object, ElfSymbolTable &symbol_table)
        : m_object(object), m_symbol_table(symbol_table) { }
    virtual ~TrampolineBuilder() { }

    // Build the trampoline instructions.
    std::tuple<Elf_SectionIndex, ElfSymbolTable::SymbolMapping>
    build_trampolines(const EntrySymbols &entry_symbols);

protected:
    virtual ElfObject::DataBuffer
    create_trampoline_data(const EntrySymbols &entry_symbols) = 0;

    virtual void
    add_reloc(ElfSymbolTable::SymbolRef symbol_index, GElf_Addr trampoline_offset) = 0;

    virtual void
    target_postprocessing(unsigned tramp_section_index) = 0;

    virtual size_t
    trampoline_size() const = 0;

    std::map<ElfSymbolTable::SymbolRef, GElf_Addr> m_trampoline_offsets;
    Elf_RelocBuffer m_trampoline_relocs;
    ElfObject &m_object;
    ElfSymbolTable &m_symbol_table;
};

class TrapRecordBuilder {
public:
    TrapRecordBuilder(bool include_sizes = false)
        : m_object(nullptr),
          m_section_symbol(), m_section_p2align(0),
          m_new_section_symbol(false),
          m_has_func_symbols(false),
          m_in_group(false),
          m_reloc_section_ndx(0),
          m_padding_offset(0), m_padding_size(0),
          m_include_sizes(include_sizes) { }

    void set_object(const ElfObject *object) {
        assert((m_object == nullptr || m_object == object) &&
               "Attempting to set TrapLinker object pointer to different value");
        m_object = object;
    }

    void set_section_symbol(ElfSymbolTable::SymbolRef section_symbol,
                            bool new_symbol = false) {
        m_section_symbol = section_symbol;
        m_new_section_symbol = new_symbol;
    }

    void set_section_p2align(Elf_Offset section_p2align) {
        m_section_p2align = section_p2align;
    }

    void set_has_func_symbols() {
        m_has_func_symbols = true;
    }

    void add_entry_symbol(ElfSymbolTable::SymbolRef symbol) {
        m_entry_symbols.push_back(symbol);
    }

    const EntrySymbols &entry_symbols() const {
        return m_entry_symbols;
    }

    ElfSymbolTable::SymbolRef section_symbol() const {
        return m_section_symbol;
    }

    Elf_Offset section_p2align() const {
        return m_section_p2align;
    }

    void set_group_section(Elf_SectionIndex group_section_ndx) {
        m_in_group = true;
        m_group_section_ndx = group_section_ndx;
    }

    bool in_group() const {
        return m_in_group;
    }

    Elf_SectionIndex group_section_ndx() const {
        return m_group_section_ndx;
    }

    void set_reloc_section(Elf_SectionIndex reloc_section_ndx) {
        assert(m_reloc_section_ndx == 0 && "Found multiple reloc sections for a single .text");
        m_reloc_section_ndx = reloc_section_ndx;
    }

    Elf_SectionIndex reloc_section_ndx() const {
        return m_reloc_section_ndx;
    }

    void mark_symbol(Elf_Offset offset, ElfSymbolTable::SymbolRef symbol,
                     Elf_Offset p2align, size_t size);

    void mark_relocation(Elf_Offset offset, uint32_t type,
                         ElfSymbolTable::SymbolRef symbol);

    void mark_relocation(Elf_Offset offset, uint32_t type,
                         ElfSymbolTable::SymbolRef symbol,
                         Elf_Offset addend);

    void mark_data_ref(Elf_Offset offset);

    void mark_padding_offset(Elf_Offset offset);
    void mark_padding_size(Elf_Offset size);

    bool can_ignore_section() const {
        return !m_has_func_symbols && m_relocs.empty();
    }

    bool symbols_empty() const {
        return m_symbols.empty();
    }

    size_t symbols_size() const {
        return m_symbols.size();
    }

    void update_symbol_indices(ElfSymbolTable::SymbolMapping &symbol_mapping);

    void read_reloc_addends(ElfObject &object, Elf_Scn *section);

    void build_trap_data(const ElfSymbolTable &symbol_table);
    void write_reloc(const ElfReloc &reloc, Elf_Offset prev_offset,
                     const ElfSymbolTable &symbol_table);

    std::pair<void*, size_t> get_trap_data() const {
        return std::make_pair((void*)m_data.data(), m_data.size());
    }

    const Elf_RelocBuffer &get_trap_reloc_data() const {
        return m_reloc_data;
    }


    friend std::ostream& operator<<(std::ostream &os, const TrapRecordBuilder &builder);

private:
    void push_back_uleb128(Elf_Offset x);
    void push_back_sleb128(Elf_Offset x);

    template<typename IntType>
    void push_back_int(IntType x, size_t max_bytes) {
      for (size_t i = 0; i < sizeof(IntType) && i < max_bytes; ++i) {
          m_data.push_back(static_cast<uint8_t>((x >> i*8) & 0xff));
      }
    }

    const ElfObject *m_object;

    ElfSymbolTable::SymbolRef m_section_symbol;
    Elf_Offset m_section_p2align;
    bool m_new_section_symbol;
    bool m_has_func_symbols;
    EntrySymbols m_entry_symbols;

    bool m_in_group;
    Elf_SectionIndex m_group_section_ndx;

    Elf_SectionIndex m_reloc_section_ndx;

    std::vector<TrapSymbol> m_symbols;
    std::vector<ElfReloc> m_relocs;
    std::vector<size_t> m_addendless_relocs;
    std::vector<Elf_Offset> m_data_refs;

    Elf_Offset m_padding_offset;
    Elf_Offset m_padding_size;

    bool m_include_sizes;

    std::vector<uint8_t> m_data;
    Elf_RelocBuffer m_reloc_data;
};

