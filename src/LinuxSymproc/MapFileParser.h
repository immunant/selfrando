/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Tommaso Frassetto, TU Darmstadt.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <map>

using std::ifstream; using std::string; using std::getline;
using std::hex; using std::vector; using std::set; using std::map;

class MapFileParser {
public:

    struct Symbol {
        uintptr_t offset;
        string name;

        Symbol(uintptr_t offset, const string &name) : offset(offset), name(name) {}
    };

    struct ObjectFileExecSection {
        string name;
        uintptr_t offset;
        unsigned long int length;
        string file_name;

        ObjectFileExecSection(const string &name, uintptr_t offset,
                              unsigned long length, const string &file_name)
                : name(name), offset(offset), length(length), file_name(file_name) {}
    };

    typedef map<string, map<string, std::pair<string, size_t>>> SectionsMapType;

private:
    // map from the name of the output section to the data of source sections in .o files
    map<string, vector<ObjectFileExecSection>> _original_sections;

    // map from (object file name, object section) to (output section name, index)
    SectionsMapType _sections_map;

public:
    // map from the name of the output section to the data of source sections in .o files
    const map<string, vector<ObjectFileExecSection>>& original_sections = _original_sections;

    // map from (object file name, object section) to (output section name, index)
    SectionsMapType &sections_map = _sections_map;

private:
    void parse(const string& filename, const set<string>& sec_names) {
        ifstream ifile(filename);

        string out_sec;

        // FIXME: when using gold, memory map doesn't start until "Memory map"
        bool in_memory_map = false;

        while (true) { //TODO refactor this
            do {
                ifile >> out_sec;
                if (out_sec == "Memory") {
                    ifile >> out_sec;
                    // gold: "Memory map"; bfd: "Memory Configuration"
                    if (out_sec == "map" || out_sec == "Configuration")
                        in_memory_map = true;
                }
                while (ifile.get() != '\n' && !ifile.eof());
            } while (sec_names.count(out_sec) != 1 && !ifile.eof());
            if (ifile.eof()) break;

            vector<ObjectFileExecSection>& curr_original_section = (
                    _original_sections.emplace(out_sec, vector<ObjectFileExecSection>())
            ).first->second;

            while (ifile.get() == ' ') {

                if (ifile.peek() == '.') { // .text.fun1     0x000000000040060d       0x10 file.o
                    string name;
                    uintptr_t offset;
                    unsigned long int length;
                    string object_file_name;
                    ifile >> name >> hex >> offset >> length >> object_file_name;

                    if (in_memory_map) {
                        int idx = curr_original_section.size();
                        sections_map[object_file_name].emplace(name, std::make_pair(out_sec, idx));
                        curr_original_section.push_back(
                            ObjectFileExecSection(name, offset, length, object_file_name));
                    }
                }

                while (ifile.get() != '\n' && !ifile.eof());
            }
        }
    }

public:
    MapFileParser(const string& filename, const set<string>& sec_names) { parse(filename, sec_names); }
};
