/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <Debug.h>

#include <libelf.h>
#include <gelf.h>

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
    ElfStringTable() {}

    void initialize (Elf_Scn *section);

    size_t add_string(std::string string);

    size_t add_string(const char* string);

    std::string get_string(size_t index) {
        assert (index < m_string_table.size());
        return std::string((char*)m_string_table.data() + index);
    }

    void update(ElfObject &object);

private:
    Elf_Scn *m_section;
    std::vector<char> m_string_table;
    size_t m_initial_size;
};

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
                assert("Unknown SymbolRef source");
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
                assert("Unknown SymbolRef source");
                return 0;
            }
        }

        GElf_Sym *get() {
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
                assert("Invalid SymbolRef");
                return nullptr;
            }
        }

        bool operator <(const SymbolRef &other) const {
            if (m_source == other.m_source)
                return m_index < other.m_index;
            return m_source < other.m_source;
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

    SymbolRef get_input_symbol_ref(size_t idx) {
        if (idx >= m_input_locals.size())
            return SymbolRef(this, SymbolRef::INPUT_GLOBAL,
                             idx - m_input_locals.size());
        return SymbolRef(this, SymbolRef::INPUT_LOCAL, idx);
    }

    SymbolRef replace_symbol(SymbolRef symbol, GElf_Addr new_value,
                             Elf_SectionIndex section_index,
                             size_t new_size);

    void mark_symbol(std::string symbol_name, std::string new_name);

    SymbolRef add_local_symbol(GElf_Addr address, Elf_SectionIndex section_index,
                               std::string name, size_t size = 0);

    SymbolRef add_section_symbol(Elf_SectionIndex section_index);

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
    ElfStringTable *m_string_table;
    XindexTable m_xindex_table;

    std::vector<Elf_Scn*> m_rel_sections;
    std::vector<Elf_Scn*> m_rela_sections;

    std::vector<GElf_Sym> m_input_locals;
    std::vector<GElf_Sym> m_input_globals;
    std::vector<GElf_Sym> m_new_locals;
    std::vector<GElf_Sym> m_new_globals;
    std::vector<uint32_t> m_new_locals_xindex;
    std::vector<uint32_t> m_new_globals_xindex;
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

typedef std::vector<ElfReloc> Elf_RelocBuffer;

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

    std::tuple<std::string, uint16_t> create_trap_info(bool emit_textramp);

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

    ElfStringTable *get_string_table(Elf_SectionIndex section_index);

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
    void prune_section_builders(SectionBuilderMap *section_builders);

    bool create_trap_info_impl(bool emit_textramp);
    void add_anchor_reloc(const GElf_Shdr *header,
                          Elf_SectionIndex section_ndx,
                          Elf_SectionIndex symtab_section_ndx,
                          ElfSymbolTable::SymbolRef section_symbol,
                          size_t function_count);

    bool update_file();
    Elf* write_new_file(int fd);
    bool update_archive(std::vector<std::string> object_files, std::string archive_filename);

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
    ElfStringTable *m_section_header_strings;

    /// Number of sections, including any pending new sections to be added
    size_t m_num_sections;

    std::list<DataBuffer> m_data_buffers;

    /// New sections to be added when we write this object back
    std::vector<std::pair<GElf_Shdr, DataBuffer> > m_new_sections;

    std::map<size_t, Elf_Offset> m_section_sizes;

    std::map<uint32_t, std::map<Elf_Offset, std::pair<uint32_t, uint32_t>>> m_section_patches;

    std::vector<DataBuffer> m_replacement_data;

    std::map<Elf_SectionIndex, ElfStringTable> m_string_tables;

    std::map<Elf_SectionIndex, Elf_RelocBuffer> m_section_relocs;

    const TargetInfo *m_target_info;
};

namespace Target {
    typedef std::vector<ElfSymbolTable::SymbolRef> EntrySymbols;

    // Create an empty .rel.XXX section
    Elf_SectionIndex create_reloc_section(ElfObject &object,
                                          const std::string &section_name,
                                          Elf_SectionIndex shndx,
                                          Elf_SectionIndex symtab_shndx,
                                          const Elf_RelocBuffer &relocs);

    // Adds a relocation to an Elf_RelocBuffer structure.
    // The caller should use whatever is left in reloc.addend
    // as the actual relocated data, in case the target arch
    // does not support explicit addends.
    void add_reloc_to_buffer(Elf_RelocBuffer &buffer,
                             ElfReloc *reloc);

    // Copies an entire Elf_RelocBuffer to a section.
    void add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                               const Elf_RelocBuffer &buffer);

    template<typename RelType>
    bool check_rel_for_stubs(ElfObject &object, RelType *relocation, ptrdiff_t addend,
                             uint32_t shndx, TrapRecordBuilder &builder);

    Elf_Offset read_reloc(char* data, ElfReloc &reloc);
};

class TrampolineBuilder {
public:
    TrampolineBuilder(ElfObject &object, ElfSymbolTable &symbol_table)
        : m_object(object), m_symbol_table(symbol_table) { }

    // Build the trampoline instructions.
    Elf_SectionIndex build_trampolines(const Target::EntrySymbols &entry_symbols);

private:
    ElfObject::DataBuffer create_trampoline_data(const Target::EntrySymbols &entry_symbols);

    void add_reloc(ElfSymbolTable::SymbolRef symbol_index, GElf_Addr trampoline_offset);

    void target_postprocessing(unsigned tramp_section_index);

    size_t trampoline_size() const;

    std::map<ElfSymbolTable::SymbolRef, GElf_Addr> m_trampoline_offsets;
    Elf_RelocBuffer m_trampoline_relocs;
    ElfObject &m_object;
    ElfSymbolTable &m_symbol_table;
};

class TrapRecordBuilder {
public:
    TrapRecordBuilder(bool include_sizes = false)
        : m_section_symbol(), m_section_p2align(0),
          m_new_section_symbol(false),
          m_has_func_symbols(false),
          m_in_group(false),
          m_reloc_section_ndx(0),
          m_padding_offset(0), m_padding_size(0),
          m_include_sizes(include_sizes) { }

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

    const Target::EntrySymbols &entry_symbols() const {
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

    void read_reloc_addends(Elf_Scn *section);

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

    ElfSymbolTable::SymbolRef m_section_symbol;
    Elf_Offset m_section_p2align;
    bool m_new_section_symbol;
    bool m_has_func_symbols;
    Target::EntrySymbols m_entry_symbols;

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

