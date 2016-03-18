/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Tommaso Frassetto, TU Darmstadt.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <vector>
#include <map>
#include <regex>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>
#include <elfio/elf_types.hpp>
#include "MapFileParser.h"

using namespace ELFIO;
using std::cout; using std::cerr; using std::dec; using std::hex; using std::endl;
using std::string; using std::vector; using std::map; using std::sort;

namespace ELFIO {
    class elfio;
    class section;
}


class ObjectFileParser {
public:
    struct Symbol {
        string name;
        Elf64_Addr start;
        Elf_Xword size;
        unsigned char type;
        Elf_Half section_index;
        Symbol(string name, Elf64_Addr start, Elf_Xword size,
               unsigned char type, Elf_Half section_index)
            : name(name), start(start), size(size),
              type(type), section_index(section_index) {}
        bool operator< (const Symbol& oth) const { return start < oth.start; }
        Symbol with_offset(unsigned long int sec_offset) const {
            Symbol res(*this);
            res.start += sec_offset;
            return res;
        }
    };

    struct Relocation {
        Elf64_Addr offset;
        Elf_Word type;
        bool write_addend = false;
        Elf_Sxword addend;

        bool has_target = false;
        Elf64_Addr target = 0;

        Relocation(Elf64_Addr offset, Elf_Word type, Elf_Sxword addend)
            : offset(offset), type(type), addend(addend) {}
        bool operator< (const Relocation& oth) const { return offset < oth.offset; }
        Relocation with_offset(unsigned long int sec_offset) const {
            Relocation res(*this);
            res.offset += sec_offset;
            return res;
        }
        void set_target(Elf64_Addr new_target) {
            has_target = true;
            target = new_target;
        }
        void set_write_addend() {
            write_addend = true;
        }
    };

    struct Section {
        string name;
        Elf64_Addr address;
        Elf_Xword size;
        bool executable, allocated;
        vector<Symbol> sym_vec;
        vector<Relocation> relo_vec;

        Section(string name, Elf64_Addr address, Elf_Xword size, bool executable, bool allocated) :
                name(name), address(address), size(size), executable(executable), allocated(allocated) {}
        Section(const string &name, Elf64_Addr address, bool executable, bool allocated, const vector<Symbol> &sym_vec,
                          const vector<Relocation> &relo_vec)
                : name(name), address(address), executable(executable), allocated(allocated), sym_vec(sym_vec),
                  relo_vec(relo_vec) {}
    };

    struct NonExecutableRelocations {
        vector<Relocation> relo_vec;
    };


    const map<Elf_Half, Section>& sections = _sections;

    const Section & section_by_name(const string& name) {
        return _sections.at(_section_id_by_name.at(name));
    }

    const vector<Symbol>& symbols = _symbols;

    const Symbol& symbol_by_name(const string& name) const {
        auto sym_idx = _symbol_id_by_name.at(name);
        return _symbols.at(sym_idx);
    }

    virtual ~ObjectFileParser();

protected:
    const string filename;
    vector<string> tmpfiles;
    map<Elf_Half, Section> _sections;
    map<string, unsigned int> _section_id_by_name;
    vector<Symbol> _symbols;
    map<string, unsigned int> _symbol_id_by_name;
    elfio* reader = NULL;

    void load_sections();
    void load_symbols();
    ObjectFileParser(const string &filename) : filename(filename) {}

    //forbid copies to prevent ELFIO corruption
    ObjectFileParser(const ObjectFileParser& oth) = delete;

    void elfio_init();
    void elfio_delete();
};

class ExecFileParser: public ObjectFileParser {
    section*txtsec = NULL;
    section* xpsec = NULL;
    vector<Elf64_Addr> NOP_symbols;
    NonExecutableRelocations _eh_frame_relocations;

public:
    ExecFileParser(const string& filename): ObjectFileParser(filename) {
        elfio_init();
        load_sections();
        load_symbols();
        find_NOPs();
        load_eh_frame_relocations();
        // no elfio_delete() since it is needed for output
    }

    void find_NOPs();

    void add_txtrp_section(const vector<Section>& sections, const NonExecutableRelocations& non_exec);

    const NonExecutableRelocations& eh_frame_relocations = _eh_frame_relocations;

private:
    void load_eh_frame_relocations();
    void append_uleb128(uint64_t i);
    void append_ptr(void* t);
    void append_got();
    void append_nops();
    void append_trap_header(char version, unsigned int flags);
    void append_trap_record(const Section & esec);
    void append_non_exec_relocations(const NonExecutableRelocations& non_exec);
    void append_export_trampolines();
};



class DotOFileParser: public ObjectFileParser {
    void load_relocations();

public:
    DotOFileParser(const string& filename) : ObjectFileParser(filename) {
        elfio_init();
        load_sections();
        load_symbols();
        load_relocations();
        elfio_delete();
    }
};

