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

#include <Windows.h>
#include <tchar.h>

#include <cstdint>
#include <cassert>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>

#include "COFF.h"

#define VERBOSE 0

static const char kTrapSectionName[] = ".txtrp$d";
static const char kExportSectionName[] = ".edata";
static const char kTrampolineSectionName[] = ".xptramp";

// Special @feat.00 symbol that the assembler/compiler adds to mark the object file as SAFESEH-compatible (and maybe other reasons as well)
static IMAGE_SYMBOL kFeatSymbol = { {'@', 'f', 'e', 'a', 't', '.', '0', '0' }, 0x11, IMAGE_SYM_ABSOLUTE, IMAGE_SYM_TYPE_NULL, IMAGE_SYM_CLASS_STATIC, 0 };

class BackedCOFFSection {
public:
    BackedCOFFSection() = delete;

    BackedCOFFSection(const char *name, DWORD characteristics) {
        m_hdr_backend.reset(new IMAGE_SECTION_HEADER);
        m_data_backend.reset(new std::vector<BYTE>);
        m_reloc_backend.reset(new std::vector<IMAGE_RELOCATION>);

        // Set some header fields
        memset(m_hdr_backend.get(), 0, sizeof(IMAGE_SECTION_HEADER));
        memcpy(m_hdr_backend->Name, name, IMAGE_SIZEOF_SHORT_NAME); // FIXME: handle shorter names
        m_hdr_backend->Characteristics = characteristics;
        m_frozen = false;
    }

    void addDataByte(BYTE b) {
        assert(!m_frozen && "Attempting to modify frozen section");
        m_data_backend->push_back(b);
        m_hdr_backend->SizeOfRawData++;
    }

    void addRelocation(const IMAGE_RELOCATION &reloc) {
        assert(!m_frozen && "Attempting to modify frozen section");
        m_reloc_backend->push_back(reloc);
        m_hdr_backend->NumberOfRelocations++;
    }

    size_t getDataSize() const {
        return m_data_backend->size();
    }

    size_t getNumRelocations() const {
        return m_reloc_backend->size();
    }

    operator COFFSection () {
        m_frozen = true;
        return COFFSection(m_hdr_backend.get(), m_data_backend->data(), m_reloc_backend->data());
    }

	// Convert argument to a variable-length quantity using DWARF's ULEB128 format.
    void addULEB128(size_t x) {
        if (x == 0) {
            addDataByte(0);
            return;
        }
        while (x >= 0x80) {
            addDataByte(0x80 | (x & 0x7F));
            x >>= 7;
        }
        assert((x > 0 && x < 0x80) && "Invalid value for ULEB128");
        addDataByte(static_cast<BYTE>(x));
    }

private:
    // FIXME: for some reason, unique_ptr won't work here
    std::auto_ptr<IMAGE_SECTION_HEADER> m_hdr_backend;
    std::auto_ptr<std::vector<BYTE>> m_data_backend;
    std::auto_ptr<std::vector<IMAGE_RELOCATION>> m_reloc_backend;
    bool m_frozen;
};

// FIXME: These need to be global for now, so their contents
// don't get freed before being written to disk
// FIXME: until we make them temporary, they're a memory leak
std::vector<BackedCOFFSection> new_sections;
std::vector<std::unique_ptr<IMAGE_SYMBOL>> new_symbols;

static bool ReadEntireFile(const _TCHAR *file, std::shared_ptr<BYTE> *file_contents, size_t *file_size_ptr) {
    FILE *fp;
    int err = _tfopen_s(&fp, file, TEXT("rb"));
    if (err) {
        // FIXME: copy err somewhere
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    assert(file_size != -1 && "Invalid file size");
    if (file_size_ptr != nullptr)
        *file_size_ptr = file_size;
    //printf("Total file size: %ld\n", file_size);

    file_contents->reset(new BYTE[file_size], std::default_delete<BYTE[]>());
    fseek(fp, 0, SEEK_SET);
    long file_read = fread(file_contents->get(), 1, file_size, fp);
    if (file_read < file_size) {
        file_contents->reset();
        if (file_size_ptr != nullptr)
            *file_size_ptr = 0;
        return false;
    }
    fclose(fp);
    return true;
}

// Returns true upon success and false otherwise.
TRaPStatus TRaPCOFFObject(const _TCHAR *input_file, const _TCHAR *output_file) {
    COFFObject coff_file;
    auto read_ok = coff_file.readFromFile(input_file);
	if (!read_ok) {
		if (VERBOSE)
			fwprintf_s(stderr, L"Failed to parse file '%s'\n", input_file);
		return TRaPStatus::TRAP_ERROR;
	}
    auto trap_added = coff_file.createTRaPInfo();
	if (!trap_added) {
		if (VERBOSE)
			fwprintf_s(stderr, L"Didn't add TRaP info to '%s'\n", input_file);
		return TRaPStatus::TRAP_FOUND; // If TRaPCOFF returned false, the file already had TRaP info
	}
    if (!coff_file.writeToFile(output_file))
        return TRaPStatus::TRAP_ERROR;
    return TRaPStatus::TRAP_ADDED;
}

TRaPStatus TRaPCOFFLibrary(COFFLibrary *lib) {
    TRaPStatus res = TRaPStatus::TRAP_FOUND;
    for (auto &obj_ptr : lib->objects()) {
        if (obj_ptr) {
            auto added_trap = obj_ptr->createTRaPInfo();
            if (added_trap)
                res = TRaPStatus::TRAP_ADDED;
        }
    }
    // If any object file receives a .txtrp section, return true
    return res;
}

TRaPStatus TRaPCOFFLibrary(const _TCHAR *input_file, const _TCHAR *output_file) {
	COFFLibrary coff_lib;
	auto read_ok = coff_lib.readFromFile(input_file);
	if (!read_ok) {
		if (VERBOSE)
			fwprintf_s(stderr, L"Failed to parse library '%s'\n", input_file);
        return TRaPStatus::TRAP_ERROR;
	}
	auto trap_status = TRaPCOFFLibrary(&coff_lib);
	if (trap_status != TRaPStatus::TRAP_ADDED) {
		if (VERBOSE)
			fwprintf_s(stderr, L"Didn't add TRaP info to '%s'\n", input_file);
        return trap_status;
    }
    if (!coff_lib.writeToFile(output_file))
        return TRaPStatus::TRAP_ERROR;
    return TRaPStatus::TRAP_ADDED;
}

bool ConvertExports(COFFObject *exp, COFFObject *tramp) {
    auto edata_sec = exp->findSection(kExportSectionName);
    if (edata_sec == nullptr)
        return false;

    // Fill in the header of the trampoline object file
    auto tramp_hdr = tramp->header();
    memcpy(tramp_hdr, exp->header(), sizeof(IMAGE_FILE_HEADER));
    tramp_hdr->NumberOfSections = tramp->sections().size();
    tramp_hdr->NumberOfSymbols = tramp->symbols().size();

    // Add in the SAFESEH/feat.00 symbol
    tramp->addSymbol(COFFSymbol(&kFeatSymbol, nullptr));

    // Add in the new section
    auto tramp_sec_chars = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    new_sections.emplace_back(kTrampolineSectionName, tramp_sec_chars);
    auto &tramp_sec = new_sections.back();

    WORD rel32_rel_type = (exp->header()->Machine == IMAGE_FILE_MACHINE_I386) ? IMAGE_REL_I386_REL32 : IMAGE_REL_AMD64_REL32;
    for (auto &sym : exp->symbols())
        if (sym.header()->StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
            // Bingo: we found an external symbol; add a trampoline for it and copy the symbol
            auto sym_index = tramp->symbols().size();
            tramp_sec.addDataByte(0xE9); // JMP <symbol>
            auto jmp_ofs_pos = tramp_sec.getDataSize();
            tramp_sec.addDataByte(0);
            tramp_sec.addDataByte(0);
            tramp_sec.addDataByte(0);
            tramp_sec.addDataByte(0);
            // TODO: align the jumps to 8-bytes or more???
            tramp_sec.addRelocation(IMAGE_RELOCATION{ jmp_ofs_pos, sym_index, rel32_rel_type });
            // Copy the symbol as-is to the trampoline file
            tramp->addSymbol(sym);
            // TODO: also add .txtrp TRaP info for this jump
        }
    tramp->addSection(tramp_sec);

    // Copy over string table from exp, as most symbols and symbol names are identical
    tramp->setStringTable(const_cast<char*>(exp->stringTable()));
    return true;
}

bool ConvertExports(const _TCHAR *input_file, const _TCHAR *output_file) {
    COFFObject exp_file;
    auto read_ok = exp_file.readFromFile(input_file);
    if (!read_ok)
        return false;

    IMAGE_FILE_HEADER tramp_hdr;
    COFFObject tramp_file(COFFObject::fromRawData(&tramp_hdr));
    auto converted = ConvertExports(&exp_file, &tramp_file);
    if (!converted)
        return false;
    return tramp_file.writeToFile(output_file);
}

COFFSection::COFFSection(COFFObject *file, IMAGE_SECTION_HEADER *hdr) : m_file(file), m_hdr(hdr) {
    m_data = file->filePtr(hdr->PointerToRawData);
    m_relocs = file->filePtr<IMAGE_RELOCATION>(hdr->PointerToRelocations);
}

COFFSection::COFFSection(IMAGE_SECTION_HEADER *hdr, void *data, IMAGE_RELOCATION *relocs)
    : m_file(nullptr), m_hdr(hdr), m_data(data), m_relocs(relocs) {
}

COFFSymbol::COFFSymbol(COFFObject *file, IMAGE_SYMBOL *sym, size_t index) : m_file(file), m_sym(sym), m_index(index) {
    m_actual_name = reinterpret_cast<char*>(sym->N.ShortName);
    if (sym->N.Name.Short == 0) {
        m_actual_name = file->m_strings + sym->N.Name.Long;
    }
    m_aux_symbols = reinterpret_cast<IMAGE_AUX_SYMBOL*>(sym + 1);
#if 0
    printf("Symbol: name=%8s value=%x section=%hx type=%hx class=%hhx aux=%hhx\n",
        m_actual_name, sym->Value, sym->SectionNumber, sym->Type, sym->StorageClass, sym->NumberOfAuxSymbols);
#endif
}

size_t COFFSymbol::writeToFile(FILE *f) {
    size_t res = 0;
    res += fwrite(m_sym, sizeof(IMAGE_SYMBOL), 1, f);
    res += fwrite(m_aux_symbols, sizeof(IMAGE_AUX_SYMBOL), m_sym->NumberOfAuxSymbols, f);
    return res; // FIXME: better error handling
}

bool COFFObject::parse() {
    if (header()->Machine != IMAGE_FILE_MACHINE_I386 &&
        header()->Machine != IMAGE_FILE_MACHINE_AMD64)
        return false;
#if 0
    printf("Read header machine:%hx sections:%d symbols:%d chars:%hx\n",
        header()->Machine, header()->NumberOfSections, header()->NumberOfSymbols, header()->Characteristics);
#endif

    // Read sections
    IMAGE_SECTION_HEADER *sec_hdr = reinterpret_cast<IMAGE_SECTION_HEADER*>(header() + 1);
    m_sections.clear();
    for (size_t sec = 0; sec < header()->NumberOfSections; sec++, sec_hdr++)
        m_sections.emplace_back(this, sec_hdr);

    assert(header()->PointerToSymbolTable != 0 && "Missing symbol table");
    IMAGE_SYMBOL *sym_ptr = filePtr<IMAGE_SYMBOL>(header()->PointerToSymbolTable);

    // Build string table
    m_strings = reinterpret_cast<char*>(sym_ptr + header()->NumberOfSymbols);

    // Build symbol table
    m_symbols.clear();
    for (size_t sym = 0; sym < header()->NumberOfSymbols; sym++, sym_ptr++) {
        BYTE num_aux = sym_ptr->NumberOfAuxSymbols;
        m_symbols_by_index[sym] = m_symbols.size();
        m_symbols.emplace_back(this, sym_ptr, sym);
        sym += num_aux, sym_ptr += num_aux;
    }
    return true;
}

bool COFFObject::readFromFile(const _TCHAR *filename) {
    auto read_ok = ReadEntireFile(filename, &m_file_data, nullptr);
    if (!read_ok)
        return false;
    return parse();
}

bool COFFObject::createTRaPInfo() {
    // Check if the file already contains .txtrp
    auto trap_sec = findSection(kTrapSectionName);
    if (trap_sec != nullptr)
        return false;
    // Didn't find any .txtrp sections, add them now
    std::unordered_map<SHORT, std::map<DWORD, size_t>> func_sym_info;
    WORD sym_rel_type = (header()->Machine == IMAGE_FILE_MACHINE_I386) ? IMAGE_REL_I386_DIR32NB : IMAGE_REL_AMD64_ADDR32NB;
    WORD rel32_rel_type = (header()->Machine == IMAGE_FILE_MACHINE_I386) ? IMAGE_REL_I386_REL32 : IMAGE_REL_AMD64_REL32;
    for (auto &sym : symbols()) {
        auto sec_idx = sym.header()->SectionNumber;
        if (sec_idx <= 0 || sec_idx > IMAGE_SYM_SECTION_MAX)
            continue;
        auto &sec = sections()[sec_idx - 1];
        if ((sec.header()->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        if (sec.dataSize() == 0)
            continue;
        if (sym.header()->Value >= sec.dataSize())
            continue;
#if RANDOLIB_TRAP_ALL_SYMBOLS
        if (!ISFCN(sym.header()->Type))
            continue;
#endif
        func_sym_info[sec_idx][sym.header()->Value] = sym.index();
    }
    for (auto &sym_info : func_sym_info) {
        auto &sec = sections()[sym_info.first - 1];
        auto sec_hdr = sec.header();
        assert((sec_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && "Found function with non-executable code");

        // Get a pointer to the first (earliest) symbol inside this section
        auto first_sym_it = sym_info.second.begin();
        assert(first_sym_it != sym_info.second.end() && "Section contains empty map of symbols");

        auto new_sec_chars = (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ | IMAGE_SCN_LNK_COMDAT);
        new_sections.emplace_back(kTrapSectionName, new_sec_chars);
        auto &new_sec = new_sections.back();

        // Add 4-byte placeholder for final address of function; FIXME: 4-byte alignment???
        new_sec.addDataByte(0);
        new_sec.addDataByte(0);
        new_sec.addDataByte(0);
        new_sec.addDataByte(0);
        if (header()->Machine == IMAGE_FILE_MACHINE_AMD64) {
            // FIXME: we're cheating a bit here: the field needs to be 64 bits wide on all OSes
            // but we only have a 32-bit ADDR32NB relocation; for now, we'll just leave the
            // upper 4 bytes zeroed out. Hopefully, this will all be fixed when we implement
            // abbrevs
            new_sec.addDataByte(0);
            new_sec.addDataByte(0);
            new_sec.addDataByte(0);
            new_sec.addDataByte(0);
        }
        new_sec.addRelocation(IMAGE_RELOCATION{ 0, first_sym_it->second, sym_rel_type });

        // Compute the symbol padding (if needed)
        size_t sec_p2align = ((sec_hdr->Characteristics & IMAGE_SCN_ALIGN_MASK) / IMAGE_SCN_ALIGN_1BYTES) - 1;
        size_t new_p2align = sec_p2align;

        // The first symbol might not start at the beginning of the section, so encode its offset
        // FIXME: could we encode this inside the relocation itself???
        new_sec.addULEB128(first_sym_it->first);
        // Encode all symbols that point to this section, in increasing order of offset
        auto sec_ofs = first_sym_it->first;
#if RANDOLIB_TRAP_ALL_SYMBOLS
        auto it = first_sym_it;
        for (++it; it != sym_info.second.end(); ++it) {
            auto new_ofs = it->first;
            assert(new_ofs > sec_ofs && "Symbol offsets not strictly increasing");
            new_sec.addULEB128(new_ofs - sec_ofs); // Size of the previous symbol
#if RANDOLIB_ALIGN_FUNCTIONS
            new_sec.addULEB128(new_p2align);
            new_p2align = 0; // FIXME: set to sec_p2align instead???
#endif
            new_sec.addULEB128(new_ofs - sec_ofs); // Offset to the current symbol
            sec_ofs = new_ofs;
        }
#endif
        assert(sec_ofs < sec.dataSize() && "Zero-sized symbol");
        new_sec.addULEB128(sec.dataSize() - sec_ofs); // Size of the last symbol
#if RANDOLIB_ALIGN_FUNCTIONS
        new_sec.addULEB128(new_p2align);              // Alignment of the last symbol (log2)
        new_sec.addULEB128(0);
#endif
        new_sec.addULEB128(0);
        new_sec.addULEB128(0);

        // Add section-relative relocations
        auto sec_relocs = sec.relocations();
        size_t sec_pos = 0;
        for (size_t i = 0; i < sec_hdr->NumberOfRelocations; i++) {
            auto &reloc = sec_relocs[i];
            // FIXME: make this prettier
            if (reloc.Type == rel32_rel_type ||
                (header()->Machine == IMAGE_FILE_MACHINE_AMD64 &&
                 reloc.Type >= IMAGE_REL_AMD64_ADDR32NB &&
                 reloc.Type <= IMAGE_REL_AMD64_REL32_5)) {
                assert(reloc.VirtualAddress > sec_pos && "Found REL32 relocation with offset 0");
                new_sec.addULEB128(reloc.VirtualAddress - sec_pos);
                new_sec.addULEB128(reloc.Type);
                sec_pos = reloc.VirtualAddress;
            }
        }
        new_sec.addULEB128(0);
        new_sec.addULEB128(0);

        // Create and set the symbol for the new section
        new_symbols.emplace_back(new IMAGE_SYMBOL);
        auto new_sec_symbol = new_symbols.back().get();
        memset(new_sec_symbol, 0, sizeof(IMAGE_SYMBOL));
        memcpy(new_sec_symbol->N.ShortName, kTrapSectionName, 8);
        new_sec_symbol->SectionNumber = 1 + sections().size();
        new_sec_symbol->Type = IMAGE_SYM_TYPE_NULL;
        new_sec_symbol->StorageClass = IMAGE_SYM_CLASS_STATIC;
        new_sec_symbol->NumberOfAuxSymbols = 1;

        // Create and set the aux symbol
        new_symbols.emplace_back(new IMAGE_SYMBOL);
        auto new_aux_symbol = reinterpret_cast<IMAGE_AUX_SYMBOL*>(new_symbols.back().get());
        memset(new_aux_symbol, 0, sizeof(IMAGE_AUX_SYMBOL));
        new_aux_symbol->Section.Length = new_sec.getDataSize();
        new_aux_symbol->Section.NumberOfRelocations = new_sec.getNumRelocations();
        new_aux_symbol->Section.Selection = IMAGE_COMDAT_SELECT_ASSOCIATIVE;
        new_aux_symbol->Section.Number = sym_info.first; // FIXME: this could lead to .txtrp disappearing sometimes???

        // Add the new section and two new symbols
        addSection(new_sec);
        addSymbol(COFFSymbol(new_sec_symbol, new_aux_symbol));
    }
    return true;
}


#if 0
void COFFObject::parse_debug_s(void *debug_data, uint32_t debug_size) {
    uint32_t *debug_ptr = (uint32_t*)debug_data,
        *debug_end = debug_ptr + (debug_size / 4);
    assert(debug_ptr[0] == 0x4 && "Invalid debug$S signature");
    debug_ptr++;
    while (debug_ptr < debug_end) {
        uint32_t type = debug_ptr[0],
            len = debug_ptr[1];
        printf("Debug type=%x len=%d\n", type, len);
        if (type == 0xf5) {
            for (size_t i = 0; i < (len / 4); i++)
                printf("F5 word %d: %08x\n", i, debug_ptr[i + 2]);
        }
        debug_ptr += 2 + (len + 3) / 4;
    }
}
#endif

const COFFSection *COFFObject::findSection(const char *name) const {
    // The Name field in the section header is 8 bytes long
    // It either contains an 8-char name, or a shorted one padded with \0
    // Whatever the caller passes in name, we need to convert to this format
    // FIXME: support long section names
    char short_name[IMAGE_SIZEOF_SHORT_NAME + 1]; // Holds the first 8 characters of name, followed by a \0
    strcpy_s(short_name, name);
    auto short_len = strlen(short_name);
    if (short_len < IMAGE_SIZEOF_SHORT_NAME)
        memset(short_name + short_len, 0, IMAGE_SIZEOF_SHORT_NAME - short_len);
    for (auto &sec : m_sections)
        if (memcmp(sec.header()->Name, short_name, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return &sec;
    return nullptr;
}

void COFFObject::writeToFile(FILE *f) {
    // FIXME: handle errors
    header()->NumberOfSections = m_sections.size();
    size_t file_pos = sizeof(IMAGE_FILE_HEADER) + header()->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    for (auto &sec : m_sections) {
        sec.placeAtPos(file_pos);
        file_pos += sec.dataSize();
        file_pos += sec.relocSize();
    }
    auto old_sym_ptr = header()->PointerToSymbolTable;
    header()->PointerToSymbolTable = file_pos;

    // Caller is responsible for moving file pointer to start of file
    fwrite(header(), sizeof(IMAGE_FILE_HEADER), 1, f);
    for (auto &sec : m_sections)
        sec.writeHeaderToFile(f);
    for (auto &sec : m_sections) {
        sec.writeDataToFile(f);
        sec.writeRelocsToFile(f);
    }

    // Write out symbols
    auto sym_ptr = filePtr<IMAGE_SYMBOL>(old_sym_ptr);
    for (auto &sym : m_symbols)
        sym.writeToFile(f);

    // ...and string table
    uint32_t strings_size = *reinterpret_cast<uint32_t*>(m_strings);
    fwrite(m_strings, strings_size, 1, f);
}

bool COFFObject::writeToFile(const _TCHAR *filename) {
    FILE *fp;
    int err = _tfopen_s(&fp, filename, TEXT("wb"));
    if (err) {
        if (VERBOSE)
            fwprintf_s(stderr, L"Failed to write trapped file '%s'\n", filename);
        return false;
    }
    writeToFile(fp);
    fclose(fp);
    if (VERBOSE)
        fwprintf_s(stderr, L"Success: added TRaP info to '%s'\n", filename);
    return true;
}

size_t COFFObject::totalSize() const {
    size_t res = sizeof(IMAGE_FILE_HEADER);
    for (auto &sec : m_sections)
        res += sec.totalSize();
    for (auto &sym : m_symbols)
        res += sym.totalSize();
    uint32_t strings_size = *reinterpret_cast<uint32_t*>(m_strings);
    res += strings_size;
    return res;
}

template<typename T>
static T ReadBigEndian(T *ptr) {
    auto b_ptr = reinterpret_cast<BYTE*>(ptr);
    T res = 0;
    for (size_t i = 0; i < sizeof(T); i++) {
        res <<= 8;
        res |= b_ptr[i];
    }
    return res;
}

template<typename T>
static void WriteBigEndian(T *ptr, T val) {
    auto b_ptr = reinterpret_cast<BYTE*>(ptr);
    for (size_t i = sizeof(T); i > 0; i--) {
        b_ptr[i - 1] = val & 0xff;
        val >>= 8;
    }
}

bool COFFLibrary::parse() {
    auto file_start = m_file_data.get();
    auto file_end = file_start + m_file_size;
    if (memcmp(file_start, IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE) != 0)
        return false; // File is not an archive

    auto ptr = file_start;
    ptr += IMAGE_ARCHIVE_START_SIZE;

    std::unordered_map<ptrdiff_t, size_t> pointer_map;
    m_members.clear();
    m_objects.clear();
    while (ptr < file_end) {
        pointer_map[ptr - file_start] = m_members.size();
        auto hdr = reinterpret_cast<IMAGE_ARCHIVE_MEMBER_HEADER*>(ptr);
        ptr += sizeof(*hdr);
        assert(memcmp(hdr->EndHeader, IMAGE_ARCHIVE_END, 2) == 0 && "Invalid archive header end");

        size_t member_size = 0;
        for (size_t i = 0; i < sizeof(hdr->Size) && isdigit(hdr->Size[i]); i++)
            member_size = (member_size * 10) + (hdr->Size[i] - '0');

        bool is_linker_member = false, is_longnames_member = false;
        if (memcmp(hdr->Name, IMAGE_ARCHIVE_LINKER_MEMBER, sizeof(hdr->Name)) == 0)
            is_linker_member = true;
        if (memcmp(hdr->Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, sizeof(hdr->Name)) == 0)
            is_longnames_member = true;
        m_members.push_back(COFFArchiveMember{ 
            /*header*/              hdr,
            /*data*/                ptr,
            /*size*/                member_size, 
            /*is_linker_member*/    is_linker_member,
            /*is_longnames_member*/ is_longnames_member,
            /*object_idx*/          m_objects.size() });

        auto is_internal_member = (is_linker_member || is_longnames_member);
        if (!is_internal_member) {
            // Regular object (or import) member
            m_objects.emplace_back(new COFFObject(std::shared_ptr<BYTE>(m_file_data, ptr)));
            auto &obj = m_objects.back();
            if (!obj->parse()) {
                // Clear the pointer and release the COFFObject
                obj.reset();
                // TODO: save some memory by doing a pop_back()???
            }
        }
        ptr += member_size;
        // Member headers start at even offsets; the librarian adds '\n' bytes as padding
        if ((ptr - file_start) & 1)
            ptr++;
    }

    // Read in the Offset fields from the linker members
    for (auto &member : m_members)
        if (member.is_linker_member) {
            auto first_linker = m_linker_symbols.empty();
            m_linker_symbols.emplace_back(new std::vector<DWORD>());
            auto &sym_vec = *m_linker_symbols.back();

            // This format is messed up: first linker member stores values in big-endian format
            // but the second one stores them in native format (I think)
            auto ptr = reinterpret_cast<DWORD*>(member.data);
            auto num_offsets = first_linker ? ReadBigEndian<DWORD>(ptr) : *ptr;
            ptr++;
            sym_vec.resize(num_offsets);
            for (size_t i = 0; i < num_offsets; i++) {
                auto offset = first_linker ? ReadBigEndian<DWORD>(ptr) : *ptr;
                ptr++;
                if (offset > 0) {
                    // For some reason, MSVC-produced .lib files sometimes contains offsets equal to 0
                    // They're not used for anything, so we can just ignore them
                    assert(pointer_map.find(offset) != pointer_map.end() && "File offset not found in map");
                    sym_vec[i] = pointer_map[offset];
                }
            }
        }
    return true;
}

bool COFFLibrary::readFromFile(const _TCHAR *filename) {
    auto read_ok = ReadEntireFile(filename, &m_file_data, &m_file_size);
    if (!read_ok)
        return false;
    return parse();
}

void COFFLibrary::writeToFile(FILE *fp) {
    size_t curr_file_pos = IMAGE_ARCHIVE_START_SIZE;
    std::vector<size_t> offsets;
    offsets.resize(m_members.size());
    for (size_t i = 0; i < m_members.size(); i++) {
        auto &member = m_members[i];
        auto is_internal_member = (member.is_linker_member || member.is_longnames_member);
        if (!is_internal_member) {
            auto &obj_ptr = m_objects[member.object_idx];
            if (obj_ptr) {
                member.size = obj_ptr->totalSize();
            }
        }

        // We need to store the size in a size-11 temporary because of the terminating NUL byte
        char tmp[11];
        _snprintf_s(tmp, 11, _TRUNCATE, "%-10d", member.size);
        memcpy(member.header->Size, tmp, sizeof(member.header->Size));

        // Update the file offsets
        offsets[i] = curr_file_pos;
        curr_file_pos += sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
        curr_file_pos += member.size;
        // Pad odd-sized members with a '\n' byte
        if (member.size & 1)
            curr_file_pos++;
    }

    // Recompute Offsets arrays in linker members
    size_t curr_linker_member = 0;
    for (size_t i = 0; i < m_members.size(); i++) {
        auto &member = m_members[i];
        if (member.is_linker_member) {
            auto first_linker = (curr_linker_member == 0);
            auto &sym_vec = *m_linker_symbols[curr_linker_member];
            auto ptr = reinterpret_cast<DWORD*>(member.data);
            ptr++;
            for (size_t j = 0; j < sym_vec.size(); j++, ptr++)
                if (first_linker) {
                    WriteBigEndian<DWORD>(ptr, offsets[sym_vec[j]]);
                } else {
                    *ptr = offsets[sym_vec[j]];
                }
            curr_linker_member++;
        }
    }

    fwrite(IMAGE_ARCHIVE_START, 1, IMAGE_ARCHIVE_START_SIZE, fp);
    for (size_t i = 0; i < m_members.size(); i++) {
        auto &member = m_members[i];
        assert(ftell(fp) == offsets[i] && "Writing at invalid file offset");
        fwrite(member.header, sizeof(IMAGE_ARCHIVE_MEMBER_HEADER), 1, fp);
        bool write_raw = true;
        auto is_internal_member = (member.is_linker_member || member.is_longnames_member);
        if (!is_internal_member) {
            auto &obj_ptr = m_objects[member.object_idx];
            if (obj_ptr) {
                obj_ptr->writeToFile(fp);
                write_raw = false;
            }
        }
        if (write_raw)
            fwrite(member.data, member.size, 1, fp);
        if (member.size & 1)
            fwrite(IMAGE_ARCHIVE_PAD, 1, 1, fp);
    }
}

bool COFFLibrary::writeToFile(const _TCHAR *filename) {
    FILE *fp;
    int err = _tfopen_s(&fp, filename, TEXT("wb"));
	if (err) {
		if (VERBOSE)
			fwprintf_s(stderr, L"Failed to write trapped library '%s'\n", filename);
		return false;
	}
    writeToFile(fp);
    fclose(fp);
	if (VERBOSE)
		fwprintf_s(stderr, L"Success: added TRaP info to '%s'\n", filename);
    return true;
}