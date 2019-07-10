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

#pragma once

#include <memory>
#include <tchar.h> // FIXME: is this windows only?
#include <unordered_map>
#include <vector>

class COFFLibrary;
class COFFObject;
class COFFSection;
class COFFSymbol;

enum TRaPStatus : uint8_t {
    TRAP_ADDED,
    TRAP_FOUND,
    TRAP_ERROR,
};

extern TRaPStatus TRaPCOFFObject(COFFObject *coff);
extern TRaPStatus TRaPCOFFObject(const _TCHAR *input_file, const _TCHAR *output_file);
extern TRaPStatus TRaPCOFFLibrary(COFFLibrary *lib);
extern TRaPStatus TRaPCOFFLibrary(const _TCHAR *input_file, const _TCHAR *output_file);
extern bool ConvertExports(COFFObject *exp, COFFObject *tramp);
extern bool ConvertExports(const _TCHAR *input_file, const _TCHAR *output_file);

class COFFSection {
public:
    COFFSection(COFFObject *file, IMAGE_SECTION_HEADER *hdr);
    COFFSection(IMAGE_SECTION_HEADER *hdr, void *data, IMAGE_RELOCATION *relocs);

    const IMAGE_SECTION_HEADER *header() const {
        return m_hdr;
    }

    const IMAGE_RELOCATION *relocations() const {
        return m_relocs;
    }

    const size_t headerSize() const {
        return sizeof(IMAGE_SECTION_HEADER);
    }

    const size_t dataSize() const {
        if ((m_hdr->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
            return 0;
        return m_hdr->SizeOfRawData;
    }

    const size_t relocSize() const {
        if ((m_hdr->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
            return 0;
        return m_hdr->NumberOfRelocations * sizeof(IMAGE_RELOCATION);
    }

    void placeAtPos(size_t pos) {
        if ((m_hdr->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) {
            m_hdr->PointerToRawData = 0;
            return;
        }
        m_hdr->PointerToRawData = pos;
        if (m_hdr->NumberOfRelocations > 0) {
            // Place relocations just after data
            m_hdr->PointerToRelocations = pos + m_hdr->SizeOfRawData;
        } else {
            m_hdr->PointerToRelocations = 0;
        }
    }

    size_t writeHeaderToFile(FILE *f) {
        return fwrite(m_hdr, sizeof(IMAGE_SECTION_HEADER), 1, f);
    }

    size_t writeDataToFile(FILE *f) {
        if ((m_hdr->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
            return 0;
        return fwrite(m_data, m_hdr->SizeOfRawData, 1, f);
    }

    size_t writeRelocsToFile(FILE *f) {
        if ((m_hdr->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
            return 0;
        return fwrite(m_relocs, sizeof(IMAGE_RELOCATION), m_hdr->NumberOfRelocations, f);
    }

    size_t totalSize() const {
        return sizeof(IMAGE_SECTION_HEADER) + dataSize() + relocSize();
    }

protected:
    COFFObject *m_file;
    IMAGE_SECTION_HEADER *m_hdr;
    void *m_data;
    IMAGE_RELOCATION *m_relocs;

    COFFSection() : m_file(nullptr) {}
};

class COFFSymbol {
public:
    COFFSymbol(COFFObject *file, IMAGE_SYMBOL *sym, size_t index);
    COFFSymbol(IMAGE_SYMBOL *sym, IMAGE_AUX_SYMBOL *aux_syms) : m_file(nullptr), m_sym(sym), m_aux_symbols(aux_syms) {
        m_index = -1; // FIXME
        m_actual_name = reinterpret_cast<char*>(sym->N.ShortName);
    }

    const IMAGE_SYMBOL *header() const {
        return m_sym;
    }

    const char *name() const {
        return m_actual_name;
    }

    size_t index() const {
        return m_index;
    }

    size_t writeToFile(FILE *f);

    size_t totalSize() const {
        return sizeof(IMAGE_SYMBOL) + (m_sym->NumberOfAuxSymbols * sizeof(IMAGE_AUX_SYMBOL));
    }

private:
    COFFObject *m_file;
    IMAGE_SYMBOL *m_sym;
    size_t m_index;
    char *m_actual_name;
    IMAGE_AUX_SYMBOL *m_aux_symbols;
};

class COFFObject {
public:
    COFFObject() : m_file_data(nullptr)
    { }

    COFFObject(std::shared_ptr<BYTE> file_data) : m_file_data(file_data)
    { }

    template<typename T>
    static COFFObject fromRawData(T *data) {
        return COFFObject(std::shared_ptr<BYTE>(reinterpret_cast<BYTE*>(data), [] (BYTE *p) {}));
    }

    bool parse();

    bool readFromFile(const _TCHAR *filename);

    bool createTRaPInfo();

    const IMAGE_FILE_HEADER *header() const {
        return reinterpret_cast<const IMAGE_FILE_HEADER*>(m_file_data.get());
    }

    IMAGE_FILE_HEADER *header() {
        return reinterpret_cast<IMAGE_FILE_HEADER*>(m_file_data.get());
    }

    const std::vector<COFFSection> &sections() const {
        return m_sections;
    }

    void addSection(const COFFSection &sec) {
        m_sections.push_back(sec);
    }

    const COFFSection *findSection(const char *name) const;

    const std::vector<COFFSymbol> &symbols() const {
        return m_symbols;
    }

    void addSymbol(const COFFSymbol &sym) {
        m_symbols.push_back(sym);
        header()->NumberOfSymbols += 1 + sym.header()->NumberOfAuxSymbols;
        // TODO: set sym.m_index
    }

    COFFSymbol &getIndexSymbol(size_t idx) {
        return m_symbols[m_symbols_by_index[idx]];
    }

    const char *stringTable() const {
        return m_strings;
    }

    void setStringTable(char *strings) {
        m_strings = strings;
    }

    void writeToFile(FILE *f);

    bool writeToFile(const _TCHAR *filename);

    size_t totalSize() const;

private:
    template<typename T = void>
    T *filePtr(size_t at) {
        return reinterpret_cast<T*>(reinterpret_cast<char*>(m_file_data.get())+at);
    }

    std::shared_ptr<BYTE> m_file_data;
    std::vector<COFFSection> m_sections;
    char *m_strings;
    std::vector<COFFSymbol> m_symbols;
    std::unordered_map<size_t, size_t> m_symbols_by_index;

    friend class COFFSection;
    friend class COFFSymbol;
};

struct COFFArchiveMember {
    IMAGE_ARCHIVE_MEMBER_HEADER *header;
    BYTE *data;
    size_t size;
    bool is_linker_member, is_longnames_member;
    size_t object_idx;
};

class COFFLibrary {
public:
    COFFLibrary()
        : m_file_data(nullptr), m_file_size(0)
    { }

    COFFLibrary(std::shared_ptr<BYTE> file_data, size_t file_size)
        : m_file_data(file_data), m_file_size(file_size)
    { }

    bool parse();

    bool readFromFile(const _TCHAR *filename);

    const std::vector<std::unique_ptr<COFFObject>> &objects() const {
        return m_objects;
    }

    void writeToFile(FILE *fp);

    bool writeToFile(const _TCHAR *filename);

private:
    std::shared_ptr<BYTE> m_file_data;
    size_t m_file_size;
    std::vector<COFFArchiveMember> m_members;
    std::vector<std::unique_ptr<COFFObject>> m_objects;
    std::vector<std::unique_ptr<std::vector<DWORD>>> m_linker_symbols;
};
