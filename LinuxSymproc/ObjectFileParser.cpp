/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Tommaso Frassetto, TU Darmstadt.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <algorithm>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include "ObjectFileParser.h"
#include "elfio/elfio.hpp"

// not sure if we actually need to whitelist, but I'm going to keep this here for now
static Elf_Word RelocWhitelist[] = {
#if __i386__
    R_386_PC32,
    R_386_PLT32,
    R_386_GOTPC,
    R_386_32,
    R_386_GOT32,
    R_386_TLS_LDO_32,
    R_386_TLS_LDM,
    R_386_TLS_GD, // TODO check if TLS are needed
    R_386_GOTOFF,
#elif __amd64__
    R_X86_64_PC32,
    R_X86_64_PLT32,
    R_X86_64_GOTPCREL,
    R_X86_64_GOTPCRELX,
    R_X86_64_REX_GOTPCRELX,
    R_X86_64_GOTPC32,
    R_X86_64_32S,
    R_X86_64_32,
    R_X86_64_64,
    R_X86_64_GOT64,
    R_X86_64_PC64,
    R_X86_64_GOTPCREL64,
    R_X86_64_GOTPC64,
    R_X86_64_GOTOFF64,
    R_X86_64_TLSGD,
#else
#error Unknown CPU architecture
#endif
};

ObjectFileParser::~ObjectFileParser() {
    elfio_delete();

    for (auto tmpfile : tmpfiles) {
        unlink(tmpfile.c_str());
    }
}

void ObjectFileParser::elfio_init() {
    if (!reader)
        reader = new elfio;
}

void ObjectFileParser::elfio_delete() {
    if (reader) {
#ifdef OFPreadprint
        cout << "Deleting ELFIO for " << filename << endl;
#endif
        delete reader;
        reader = NULL;
    }
}


void ObjectFileParser::load_sections() {
#ifdef OFPreadprint
    cout << "Opening " << filename << endl;
#endif
    auto archive_match = filename.find(".a(");
    if (archive_match != string::npos) {
        //archive: /path/to/archive.a(filename.o)
        string archive_filename = filename.substr(0, archive_match+2);
        string file_filename    = filename.substr(archive_match+3, filename.length() -(archive_match+3) -1);

        char templ[] = "/tmp/archived_file_XXXXXX.o";
        auto tmpfd = mkstemps(templ, 2);
        close(tmpfd);
        string tmpfile = string(templ);
        tmpfiles.push_back(tmpfile);
        {
            pid_t pid;
            posix_spawn_file_actions_t act;
            posix_spawn_file_actions_init(&act);
            posix_spawn_file_actions_addopen(&act, 1 /*stdout*/, templ, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
            const char* const args[] = {"ar", "p", archive_filename.c_str(), file_filename.c_str(), NULL};
            // posix_spawnp(&pid, "echo", NULL, NULL, (char* const*)args, environ);
            if (0 != posix_spawnp(&pid, "ar", &act, NULL, (char* const*)args, environ))  {
                perror("Can't start ar");
                cerr << "Can't extract file " << filename << " tmpfile: " << tmpfile << endl;
                exit(15);
            }
            int status;
            if (-1 == waitpid(pid, &status, 0)) {
                perror("waitpid failed");
                exit(16);
            }
            if (WEXITSTATUS(status) != 0) {
                cerr << "ar failed. Can't extract file " << filename << " tmpfile: " << tmpfile
                << " exc: " << WEXITSTATUS(status) << endl;
                exit(17);
            }
        }

        if (!reader->load(tmpfile)) {
            cerr << "Can't find or process ELF file " << filename << " tmpfile: " << tmpfile << endl;
            exit(12);
        }
    } else if (filename.find("linker") != string::npos) {
        // linker stubs
        // ignore for now?
    } else {
        // Regular file
        if (!reader->load(filename)) {
            cerr << "Can't find or process ELF file " << filename << endl;
            exit(11);
        }
    }

    // Sections
    for (auto &psec : reader->sections) {
        if (psec->get_name().substr(0, 3) == ".sr") continue;
        _sections.emplace(psec->get_index(), Section(psec->get_name(), psec->get_address(), psec->get_size(),
                                                     /*exec?*/ 0 != (psec->get_flags() & SHF_EXECINSTR),
                                                     /*alloc?*/ 0 != (psec->get_flags() & SHF_ALLOC)));
        _section_id_by_name.emplace(psec->get_name(), psec->get_index());
    }
}

void ObjectFileParser::load_symbols() {
    // Symbols
    for (auto &psec : reader->sections) {
        if (psec->get_type() == SHT_SYMTAB) {
            const auto sec_symbols = symbol_section_accessor(*reader, psec);
            auto sym_num = sec_symbols.get_symbols_num();

            for (unsigned int i = 0; i < sym_num; ++i) {
                string name;
                Elf64_Addr value;
                Elf_Xword size;
                unsigned char bind;
                unsigned char type;
                Elf_Half section_index;
                unsigned char other;

                // Read symbol properties
                sec_symbols.get_symbol(i, name, value, size, bind, type, section_index, other);
                _symbols.emplace_back(name, value, size, type, section_index);
                _symbol_id_by_name[name] = i;

                // HACK: if the symbol is foo@bar, also add the "foo" part as a
                // symbol (the linker takes symbols from the .o files and adds
                // @XXX suffixes to them, e.g., imported functions get @plt
                // appended)
                auto at_pos = name.find('@');
                if (at_pos != string::npos)
                    _symbol_id_by_name[name.substr(0, at_pos)] = i;

                // Now add function symbols to the sections
                if (type != STT_FUNC || !section_index) continue;

                // Linux-specific hack: the following 3 functions inside
                // the C runtime have PC-relative jumps that don't have
                // relocation entries, so they must be shuffled as a
                // package (they're from crtbegin.o):
                // 1) deregister_tm_clones (first one, this gets a symbol)
                // 2) register_tm_clones
                // 3) __do_global_dtors_aux
                // 4) frame_dummy
                if (name == "register_tm_clones" ||
                    name == "__do_global_dtors_aux" ||
                    name == "frame_dummy")
                    continue;

                try {
                    auto &sec = _sections.at(section_index);
                    sec.sym_vec.emplace_back(name, value, size, type, section_index);
                } catch (std::out_of_range e) {} // for .sr.text


#if OFPreadprint >= 2
                printf("%4d: 0x%08llx %6lld 0x%08llx %x %2d\n", i, value, size, (value + size),
                       static_cast<int>(type), static_cast<int>(section_index));
#endif
            }
        }
    }
}

void ExecFileParser::find_NOPs() {
    try { NOP_symbols.push_back(symbol_by_name("_TRaP_Linux_PaddingBytes_text").start); }
    catch (std::out_of_range e) {}
    sort(NOP_symbols.begin(), NOP_symbols.end());
}

void ExecFileParser::append_uleb128(uint64_t i) {
    do {
        unsigned char byte = (unsigned char) (i & 0x7FU);
        i >>= 7;
        if (i != 0)
            byte |= 0x80U;
        txtsec->append_data(reinterpret_cast<char*>(&byte), 1);
    } while (i != 0);
}

void ExecFileParser::append_ptr(void* t) {
    txtsec->append_data(reinterpret_cast<char*>(&t), (Elf_Word) sizeof(t));
}

void ExecFileParser::append_trap_header(char version, unsigned int flags) {
    txtsec->append_data(&version, 1);
    txtsec->append_data(reinterpret_cast<char*>(&flags), 3);
}

void ExecFileParser::append_got() {
    auto got_sec = section_by_name(".got");
    append_ptr(reinterpret_cast<void*>(got_sec.address));
    append_ptr(reinterpret_cast<void*>(got_sec.address + got_sec.size));
}

void ExecFileParser::append_nops() {
    for (auto nop : NOP_symbols) {
        append_ptr((void*) nop);
    }
    append_ptr(0);
}

void ExecFileParser::append_trap_record(const Section & esec) {
    Elf64_Addr last_item = esec.sym_vec.front().start;
    append_ptr(reinterpret_cast<void*>(last_item));
    append_uleb128(last_item - esec.address);

    for (unsigned i = 1; i < esec.sym_vec.size(); i++)
        if (esec.sym_vec[i].start != last_item) {
            append_uleb128(esec.sym_vec[i].start - last_item);
            //append_uleb128(esec.sym_vec[i].size); // size
            last_item = esec.sym_vec[i].start;
        }
    append_uleb128(0);
    //append_uleb128(0); // size

    if (!esec.relo_vec.empty()) {
        last_item = esec.relo_vec.front().offset;
        append_uleb128(last_item - esec.address);
        append_uleb128(esec.relo_vec.front().type);
        if (esec.relo_vec.front().has_target) {
            append_ptr(reinterpret_cast<void*>(esec.relo_vec.front().target));
            append_ptr(reinterpret_cast<void*>(esec.relo_vec.front().addend));
        } else if (esec.relo_vec.front().write_addend) {
            append_ptr(reinterpret_cast<void*>(esec.relo_vec.front().addend));
        }

        for (unsigned i = 1; i < esec.relo_vec.size(); i++) {
            auto &relo = esec.relo_vec[i];
            if (relo.offset != last_item) {
                append_uleb128(relo.offset - last_item);
                append_uleb128(relo.type);
                if (relo.has_target) {
                    append_ptr(reinterpret_cast<void*>(relo.target));
                    append_ptr(reinterpret_cast<void*>(relo.addend));
                } else if (relo.write_addend) {
                    append_ptr(reinterpret_cast<void*>(relo.addend));
                }
                last_item = relo.offset;
            }
        }
    }
    append_uleb128(0);
    append_uleb128(0);
}


void ExecFileParser::append_non_exec_relocations(const NonExecutableRelocations& non_exec) {
    Elf64_Addr last_item;

    if (!non_exec.relo_vec.empty()) {
        last_item = non_exec.relo_vec.front().offset;
        append_uleb128(last_item);
        append_uleb128(non_exec.relo_vec.front().type);
        if (non_exec.relo_vec.front().has_target) {
            append_ptr(reinterpret_cast<void*>(non_exec.relo_vec.front().target));
            append_ptr(reinterpret_cast<void*>(non_exec.relo_vec.front().addend));
        } else if (non_exec.relo_vec.front().write_addend) {
            append_ptr(reinterpret_cast<void*>(non_exec.relo_vec.front().addend));
        }

        for (unsigned i = 1; i < non_exec.relo_vec.size(); i++) {
            auto &relo = non_exec.relo_vec[i];
            if (relo.offset != last_item) {
                append_uleb128(relo.offset - last_item);
                append_uleb128(relo.type);
                if (relo.has_target) {
                    append_ptr(reinterpret_cast<void*>(relo.target));
                    append_ptr(reinterpret_cast<void*>(relo.addend));
                } else if (relo.write_addend) {
                    append_ptr(reinterpret_cast<void*>(relo.addend));
                }
                last_item = relo.offset;
            }
        }
    }
    append_uleb128(0);
    append_uleb128(0);
}

void ExecFileParser::append_export_trampolines() {
    char jmp_opcode = 0x01;
    for (auto &psec : reader->sections)
        if (psec->get_type() == SHT_DYNSYM) {
            const auto symbols = symbol_section_accessor(*reader, psec);
            auto sym_num = symbols.get_symbols_num();

            for (unsigned int i = 0; i < sym_num; ++i) {
                string name;
                Elf64_Addr value;
                Elf_Xword size;
                unsigned char bind;
                unsigned char type;
                Elf_Half section_index;
                unsigned char other;

                // Read symbol properties
                symbols.get_symbol(i, name, value, size, bind, type, section_index, other);
                if (type != STT_FUNC || !section_index) continue;

                // Add a trampoline for this symbol
                xpsec->append_data(&jmp_opcode, 1);
                // For now, we append the indices of symbols
                // and let PatchEntry fix them up into relative offsets
                xpsec->append_data(reinterpret_cast<char*>(&i), 4);

#if OFPreadprint >= 2
                printf("xptramp %4d: 0x%08llx %6lld 0x%08llx %x %2d\n", i, value, size, (value + size),
                       static_cast<int>(type), static_cast<int>(section_index));
#endif
            }
        }
}

void ExecFileParser::add_txtrp_section(const vector<Section>& sections, const NonExecutableRelocations& non_exec) {
    txtsec = reader->sections.add(".txtrp");
    txtsec->set_type(SHT_PROGBITS);
    txtsec->set_addr_align(0x1000);
    txtsec->set_flags(SHF_ALLOC);

    xpsec = reader->sections.add(".xptramp");
    xpsec->set_type(SHT_PROGBITS);
    xpsec->set_addr_align(0x1000); // Needs to be page-aligned, so we can mprotect() it
    xpsec->set_flags(SHF_ALLOC);

    unsigned int flags = 0;
    flags |= 0x000001; // Starting points of functions are marked (used in the original randomization, function reordering)
    //ags |= 0x000002; // Records are pre-sorted
    //ags |= 0x000004; // Symbols also have size information (symbols vector is a vector of ULEB128 pairs)
    //ags |= 0x000008; // Records also contain information on data references (which symbols have their address taken)
    flags |= 0x000010; // Records contain relocations
    flags |= 0x000020; // Trap information contains vector of relocations outside executable sections
    flags |= 0x000040; // Contains GOT data
    flags |= 0x000080; // Contains NOPs
    append_trap_header(1, flags);

    append_non_exec_relocations(non_exec);
    append_got();
    append_nops();

    for (auto& esec : sections) {
        append_trap_record(esec);
    }

    append_export_trampolines();

    unsigned long p = 0;
    for (auto& segm : reader->segments) {
        p = std::max(p, segm->get_virtual_address() + segm->get_memory_size());
    }
    p += (0x1000 - (p % 0x1000)) % 0x1000;

    auto txtseg = reader->segments.add();
    txtseg->set_type(PT_LOAD);
    txtseg->set_flags(PF_R | PF_W);
    txtseg->add_section_index(txtsec->get_index(), txtsec->get_addr_align());
    txtseg->set_virtual_address(p);
    txtseg->set_physical_address(p);

    p += txtsec->get_size();
    p += (0x1000 - (p % 0x1000)) % 0x1000;

    auto xpseg = reader->segments.add();
    xpseg->set_type(PT_LOAD);
    xpseg->set_flags(PF_R | PF_X);
    xpseg->add_section_index(xpsec->get_index(), xpsec->get_addr_align());
    xpseg->set_virtual_address(p);
    xpseg->set_physical_address(p);

    // Ensure DEP
    for (auto& segm : reader->segments) {
        if (segm->get_type() == PT_GNU_STACK) {
            segm->set_flags(segm->get_flags() & ~PF_X);
        } else if ((segm->get_flags() & PF_X) && (segm->get_flags() & PF_W)) {
            cerr << "Found WX segment " << segm->get_index() << endl;
            exit(14);
        }
    }

    string ofile = filename + ".rand.out";
    reader->save(ofile);
    struct stat st;
    stat(ofile.c_str(), &st);
    chmod(ofile.c_str(), st.st_mode | S_IXUSR);

    cout << ".txtrp: " << hex << txtsec->get_address()
         << " .xptramp: " << hex << xpsec->get_address() << endl;
}

void DotOFileParser::load_relocations() {
    // Relocations
    for (auto &psec : reader->sections) {
        if ((reader->get_class() == ELFCLASS32 && psec->get_type() == SHT_REL) ||
            (reader->get_class() == ELFCLASS64 && psec->get_type() == SHT_RELA)) {

            try {
                Section &targetSection = _sections.at((Elf_Half) psec->get_info());
                // We need to ignore relocations on !allocated sections,
                // since they don't have memory addresses
                if (!targetSection.allocated)
                    continue;

                vector<Relocation> &relo_vec = targetSection.relo_vec;

                const auto relocations = relocation_section_accessor(*reader, psec);
                auto relo_num = relocations.get_entries_num();

                for (unsigned int i = 0; i < relo_num; ++i) {
                    Elf64_Addr offset;
                    Elf_Word symbol;
                    Elf64_Addr symbolValue;
                    std::string symbolName;
                    Elf_Word type;
                    Elf_Sxword addend;
                    Elf_Sxword calcValue;

                    relocations.get_entry(i, offset, symbolValue, symbolName, type, addend, calcValue);
                    if (strncmp(symbolName.c_str(), "_TRaP_Linux", sizeof("_TRaP_Linux")-1) == 0) continue;

                    bool elf32 = reader->get_class() == ELFCLASS32;
                    bool elf64 = reader->get_class() == ELFCLASS64;

                    if (std::find(std::begin(RelocWhitelist), std::end(RelocWhitelist), type) !=
                        std::end(RelocWhitelist)) {
                        relo_vec.push_back(Relocation(offset, type, addend));
#if OFPreadprint >= 2
                        printf("%4d: 0x%08llx 0x%08x %+lld %i\n", i, offset, symbol, addend, type);
#endif
                    } else {
                        cerr << "Unknown type " << type << " (file '" << filename << "', "
                        << "section: " << psec->get_name() << ", "
                        << "offset: " << hex << offset << dec << ", "
                        << "relo index: " << i << "/" << relo_num << ")" << endl;
                        exit(13);
                    }
                }
            } catch (std::out_of_range e) {} // for .sr.text
        }
    }

#ifdef OFPprintres
    for (auto &it : _sections) {
        if (!it.second.executable)
            continue;
        printf("sec %d: %s\n", it.first, it.second.name.c_str());

        auto &sym_vec = it.second.sym_vec;
        printf("  symbols:\n");
        sort(sym_vec.begin(), sym_vec.end());
        for (auto &jt : sym_vec) {
            printf("    %08lx %08ld\n", jt.start, jt.size);
        }

        auto &relo_vec = it.second.relo_vec;
        printf("  relocations:\n");
        sort(relo_vec.begin(), relo_vec.end());
        for (auto &jt : relo_vec) {
            printf("    %08lx %d\n", jt.offset, jt.type);
        }
    }
#endif
}

void ExecFileParser::load_eh_frame_relocations() {

    for (auto& psec : reader->sections) {
        if (psec->get_name() == ".eh_frame") { //TODO: is this portable?
            auto start = (uint32_t*) psec->get_data();

            uint32_t* p = start;

            while (*p != 0) {
                assert(*p < 0xfffffff0); //otherwise, we need to add support for 64-bit DWARF

                if (p[1]) { // FDE record
                    Elf64_Addr offset = (Elf64_Addr) (p+2) - (Elf64_Addr) start + psec->get_address();
                    _eh_frame_relocations.relo_vec.push_back(Relocation(offset, R_X86_64_PC32, 0));

                } // else CIE record, we can ignore it

                // advance p by the size of the record
                p += (*p/4) + 1;
            }
        }
    }
}
