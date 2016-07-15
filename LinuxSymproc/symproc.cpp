/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Tommaso Frassetto, TU Darmstadt.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <cassert>
#include <iostream>
#include <map>
#include <memory>
#include <algorithm>
#include <string.h>
#include "MapFileParser.h"
#include "ObjectFileParser.h"

using std::cerr; using std::endl;
using std::shared_ptr; using std::pair; using std::make_shared; using std::sort;
using std::min_element;

struct MappedSection {
    const ObjectFileParser * orig_file;
    const ObjectFileParser::Section * orig_section;
    const MapFileParser::ObjectFileExecSection* out_section;
    MappedSection(const ObjectFileParser *orig_file_p,
                  const ObjectFileParser::Section *orig_section_p,
                  const MapFileParser::ObjectFileExecSection *out_section_p)
            : orig_file(orig_file_p), orig_section(orig_section_p),
              out_section(out_section_p) {}
};

void update_rel_target(ObjectFileParser::Relocation &rel) {
#if defined __amd64__
    switch(rel.type) {
        case R_X86_64_PC32:
        case R_X86_64_PLT32:
        case R_X86_64_GOTPCREL:
        case R_X86_64_GOTPCRELX:
        case R_X86_64_REX_GOTPCRELX:
            rel.set_write_addend();
            return;
        default:
            return;
    }

#elif 0 // On all other architectures, ignore all of them for now
    Elf_Sxword rel_target = 0;
    auto &rel_sym = msec.orig_file->symbols.at(rel.symbol);
    if (rel_sym.section_index != SHN_UNDEF &&
        rel_sym.section_index != SHN_COMMON) {
        // Found the symbol in the object file
        if (rel_sym.section_index == SHN_ABS) {
            // FIXME: is this correct???
            rel_target = rel_sym.start;
        } else {
            if (orig_file_sec_map != nullptr) {
                auto &sym_sec = msec.orig_file->sections.at(rel_sym.section_index);
                auto es_it = orig_file_sec_map->find(sym_sec.name);
                if (es_it != orig_file_sec_map->end()) {
                    auto &esec_idx = es_it->second;
                    auto &esec = map_file.original_sections.at(esec_idx.first)
                                                           .at(esec_idx.second);
                    rel_target = esec.offset + rel_sym.start;
                }
            }
        }
    } else {
        auto map_it = map_file.symbols.find(rel_sym.name);
        if (map_it != map_file.symbols.end()) {
            // Found the symbol in the map file
            rel_target = map_it->second.offset;
        } else {
            // Last chance: get the symbol directly from the executable
            // FIXME: check that symbol is actually in exec_file
            auto exec_sym = exec_file.symbol_by_name(rel_sym.name);
            if (exec_sym.section_index != SHN_UNDEF)
                rel_target = exec_sym.start;
        }
    }
    if (rel_target != 0) {
        rel.set_target(rel_target);
    } else {
        rel.set_target(0);
    }
#endif
}

int main(int argc, char** argv) {
	if (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "-ffunction-sections") != 0)) {
		cerr << "Usage: " << argv[0] << " <.out file> <.map file> [-ffunction-sections]" << endl;
		return 1;
	}

    const bool ffunction_sections = argc >= 4 && strcmp(argv[3], "-ffunction-sections") == 0;

    // parse executable file
    ExecFileParser exec_file(argv[1]);

    // parse map file
    set<string> executable_sections_names;
    for (auto& xsec : exec_file.sections) {
        if (!xsec.second.name.empty())
            executable_sections_names.insert(xsec.second.name);
    }

    MapFileParser map_file(argv[2], executable_sections_names);

    // parse source .o files
    map<string, shared_ptr<DotOFileParser>> obj_files;
    for (auto& osecsp : map_file.original_sections) {
        for (auto& osec : osecsp.second) {
            if (obj_files.count(osec.file_name) == 0) // skip already parsed files
                obj_files.emplace(osec.file_name, shared_ptr<DotOFileParser>(new DotOFileParser(osec.file_name)));
        }
    }

    // compute final pointers
    vector<ObjectFileParser::Section> exec_sections;
    ObjectFileParser::NonExecutableRelocations non_exec_relocations;
    for (auto& out_secp : exec_file.sections) {
        auto& out_sec = out_secp.second;

        vector<MappedSection> mapped_sections;

        try {
            for (auto& osec : map_file.original_sections.at(out_sec.name)) {
                try {
                    DotOFileParser &orig_file = *obj_files.at(osec.file_name);
                    auto orig_section = &orig_file.section_by_name(osec.name); // may throw
                    mapped_sections.push_back(MappedSection(&orig_file, orig_section, &osec));
                } catch (std::out_of_range) { continue; }
            }
        } catch (std::out_of_range) { continue; } //TODO: hacky

        unsigned int c_symbols = 0;
        unsigned int c_relocations = 0;

        for (auto& msec : mapped_sections) {
            c_symbols += msec.orig_section->sym_vec.size();
            c_relocations += msec.orig_section->relo_vec.size();
        }

        vector<ObjectFileParser::Symbol> symbols; symbols.reserve(c_symbols);
        vector<ObjectFileParser::Relocation> relocations; relocations.reserve(c_relocations);

        if (out_sec.executable) {
            for (auto& msec : mapped_sections) {
                if (ffunction_sections) {
                    if (!msec.orig_section->sym_vec.empty()) {
                        auto min_sym = *min_element(msec.orig_section->sym_vec.begin(),
                                                    msec.orig_section->sym_vec.end());
                        symbols.push_back(min_sym.with_offset(msec.out_section->offset));
                    }
                } else {
                    for (auto &sym : msec.orig_section->sym_vec) {
                        symbols.push_back(sym.with_offset(msec.out_section->offset));
                    }
                }

                MapFileParser::SectionsMapType::mapped_type *orig_file_sec_map = nullptr;
                auto es_it = map_file.sections_map.find(msec.out_section->file_name);
                if (es_it != map_file.sections_map.end())
                    orig_file_sec_map = &es_it->second;
                for (auto& rel : msec.orig_section->relo_vec) {
                    auto exec_rel = rel.with_offset(msec.out_section->offset);
                    update_rel_target(exec_rel);
                    relocations.push_back(exec_rel);
                }
            }

            if (symbols.empty()) continue;

            sort(symbols.begin(), symbols.end());
            sort(relocations.begin(), relocations.end());

            exec_sections.push_back(ObjectFileParser::Section(out_sec.name,
                                                              exec_file.section_by_name(out_sec.name).address, true, true,
                                                              symbols, relocations));

            #ifdef MAINprint
                std::cout << out_secp.first << ": 0x" << std::hex << exec_sections.back().address << endl;

                // symbols
                std::cout << " sym" << endl;
                for (auto& sym : symbols) {
                    std::cout << "  " << std::hex << "0x" << sym.start << " 0x" << sym.size << endl;
                }

                // relocations
                std::cout << " relo" << endl;
                for (auto& relo : relocations) {
                    std::cout << "  " << std::hex << "0x" << relo.offset << " " << relo.type << endl;
                }

            #endif

        } else { // non-executable section
            for (auto& msec : mapped_sections) {
                MapFileParser::SectionsMapType::mapped_type *orig_file_sec_map = nullptr;
                auto es_it = map_file.sections_map.find(msec.out_section->file_name);
                if (es_it != map_file.sections_map.end())
                    orig_file_sec_map = &es_it->second;
                for (auto& rel : msec.orig_section->relo_vec) {
                    auto exec_rel = rel.with_offset(msec.out_section->offset);
                    update_rel_target(exec_rel);
                    non_exec_relocations.relo_vec.push_back(exec_rel);
                }
            }
        }
    }

    for (auto ehr : exec_file.eh_frame_relocations.relo_vec) {
        update_rel_target(ehr);
        non_exec_relocations.relo_vec.push_back(ehr);
    }

    sort(non_exec_relocations.relo_vec.begin(), non_exec_relocations.relo_vec.end());

    exec_file.add_txtrp_section(exec_sections, non_exec_relocations);

    return 0;
}
