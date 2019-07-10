/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <Object.h>
#include <TrapInfoRelocs.h>
#include <Debug.h>
#include <Filesystem.h>
#include <Misc.h>
#include <algorithm>

#include <fcntl.h>
#include <unistd.h>

#include <libelf.h>
#include <gelf.h>

static const char kArPathVariable[] = "SELFRANDO_ORIGINAL_AR";

extern TargetOps *x86_ops;
extern TargetOps *x86_64_ops;
extern TargetOps *arm_ops;
extern TargetOps *arm64_ops;

#ifdef EM_AARCH64
static_assert(EM_AARCH64 == 183, "Invalid value for EM_AARCH64");
#endif
const std::unordered_map<uint16_t, ElfObject::TargetInfo> ElfObject::kInfoForTargets = {
    { EM_386, {
        .none_reloc      = R_386_NONE,
        .symbol_reloc    = R_386_PC32,
        .copy_reloc      = R_386_COPY,
        .min_p2align     = 0,
        .padding_p2align = 0,
        .addr_size       = 32,
        .trap_platform   = TRAP_PLATFORM_POSIX_X86,
        .ops             = x86_ops,
        }
    },
    { EM_X86_64, {
        .none_reloc      = R_X86_64_NONE,
        .symbol_reloc    = R_X86_64_PC64,
        .copy_reloc      = R_X86_64_COPY,
        .min_p2align     = 0,
        .padding_p2align = 0,
        .addr_size       = 64,
        .trap_platform   = TRAP_PLATFORM_POSIX_X86_64,
        .ops             = x86_64_ops,
        }
    },
    { EM_ARM, {
        .none_reloc      = R_ARM_NONE,
        .symbol_reloc    = R_ARM_REL32,
        .copy_reloc      = R_ARM_COPY,
        .min_p2align     = 0,
        .padding_p2align = 1,
        .addr_size       = 32,
        .trap_platform   = TRAP_PLATFORM_POSIX_ARM,
        .ops             = arm_ops,
        }
    },
    // AArch64 information
    // we encode the values numerically here, since
    // old versions of elf.h don't have the #define's
    { 183, {                                 // EM_AARCH64
        .none_reloc      = 0,                // R_AARCH64_NONE
        .symbol_reloc    = 260,              // R_AARCH64_PREL64
        .copy_reloc      = 1024,             // R_AARCH64_COPY
        .min_p2align     = 0,
        .padding_p2align = 2,
        .addr_size       = 64,
        .trap_platform   = TRAP_PLATFORM_POSIX_ARM64,
        .ops             = arm64_ops,
        }
    },
};

ObjectType parse_object_type(int fd) {
    char magic[7];
    if(read(fd, magic, 7) == -1)
        perror("read");
    lseek(fd, 0, SEEK_SET);
    if (strncmp(magic, "\x7f" "ELF", 4) == 0
        || strncmp(magic, "!<arch>", 7) == 0) {
        Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
        if (elf) {
            Elf_Kind kind = elf_kind(elf);
            if (kind == ELF_K_NONE) {
                elf_end(elf);
                return UNKNOWN;
            } else if (kind == ELF_K_AR) {
                elf_end(elf);
                Debug::printf<4>("  static object\n");
                return STATIC_OBJECT;
            }

            GElf_Ehdr ehdr;
            gelf_getehdr(elf, &ehdr);
            elf_end(elf);
            if (ehdr.e_type == ET_DYN) {
                Debug::printf<4>("  shared object\n");
                return SHARED_OBJECT;
            } else {
                Debug::printf<4>("  static object\n");
                return STATIC_OBJECT;
            }
        } else {
            return UNKNOWN;
        }
    }

    // default to assuming that a non-ELF file is a linker script.
    Debug::printf<4>("  linker script\n");
    return LINKER_SCRIPT;
}

bool ElfObject::parse() {
    m_string_tables.clear();

    // Parse the section header string table
    size_t index;
    elf_getshdrstrndx(m_elf, &index);
    m_section_header_strings = get_string_table(index);

    elf_getshdrnum(m_elf, &m_num_sections);

    m_parsed = true;

    return true;
}

std::tuple<std::string, uint16_t> ElfObject::create_trap_info(bool emit_textramp,
                                                              bool emit_eh_txtrp,
                                                              const std::string &ar_path) {
    if (!parse())
        Error::printf("Could not parse ELF file %s\n", m_filename.c_str());

    uint16_t elf_machine = EM_NONE;
    if (is_archive()) {
        Elf_Cmd cmd = ELF_C_READ;
        Elf *archive_elf = m_elf;
        std::vector<std::string> object_files;
        while ((m_elf = elf_begin(m_fd, cmd, archive_elf)) != nullptr) {
            get_elf_header(); // Re-read the ELF header since needs_trap_info() uses it
            if (!parse())
                Error::printf("Could not parse ELF archive %s\n", m_filename.c_str());
            if (is_object()) {
                auto new_machine = m_ehdr.e_machine;
                if (new_machine != EM_NONE) {
                    if (elf_machine == EM_NONE) {
                        elf_machine = new_machine;
                    } else if (new_machine != elf_machine) {
                        Error::printf("Incompatible machine types:%hd and %hd\n",
                                      elf_machine, new_machine);
                    }
                }
            }
            if (needs_trap_info()) {
                Elf *cur_elf = m_elf;
                auto temp_file = Filesystem::create_temp_file("traplink");
                Debug::printf<2>("Writing a new sub-archive file to %s\n", temp_file.second.c_str());
                m_elf = write_new_file(temp_file.first);
                if (!parse())
                    Error::printf("Could not parse ELF archive %s\n", m_filename.c_str());
                if (create_trap_info_impl(emit_textramp, emit_eh_txtrp)) {
                    update_file();
                }
                elf_end(m_elf);
                close(temp_file.first);
                m_elf = cur_elf;
                object_files.push_back(temp_file.second);
            }

            cmd = elf_next(m_elf);
            elf_end(m_elf);
            m_parsed = false;
        }
        m_elf = archive_elf;
        m_parsed = false;
        auto archive_filename = Filesystem::get_temp_filename("traparchive");
        update_archive(ar_path, object_files, archive_filename);
#ifndef TRAPLINKER_KEEP_FILES
        for (auto filename : object_files)
            Filesystem::remove(filename);
#endif
        return std::make_tuple(archive_filename, elf_machine);
    } else {
        if (create_trap_info_impl(emit_textramp, emit_eh_txtrp)) {
            update_file();
        }
        return std::make_tuple(m_filename, m_ehdr.e_machine);
    }
}

template<size_t len>
static inline bool is_prefix(const char (&prefix)[len],
                             const std::string &str) {
    // len includes the NULL terminator, so we need to exclude it
    return str.substr(0, len - 1) == prefix;
}

static inline bool is_text_section(const std::string &name,
                                   bool include_linkonce) {
    if (include_linkonce && is_prefix(".gnu.linkonce.t", name))
        return true;
    return is_prefix(".text", name) ||
           is_prefix(".stub", name);
}

static inline bool is_ctors_section(const std::string &name) {
    return is_prefix(".ctors", name) ||
           is_prefix(".dtors", name);
}

static inline bool is_gnu_linkonce(const std::string &name) {
    return is_prefix(".gnu.linkonce", name);
}

static inline bool is_linkonce_x86_pic_thunk(const std::string &name) {
    return is_prefix(".gnu.linkonce.t.__x86.get_pc_thunk", name);
}

ElfObject::SectionBuilderMap
ElfObject::create_section_builders(ElfSymbolTable *symbol_table) {
    SectionBuilderMap section_builders;
    Elf_Scn *cur_section = nullptr;
    while ((cur_section = elf_nextscn(m_elf, cur_section)) != nullptr) {
        GElf_Shdr section_header;
        auto cur_shndx = elf_ndxscn(cur_section);
        if (gelf_getshdr(cur_section, &section_header) == nullptr) {
            Error::printf("Could not parse section header: %s\n", elf_errmsg(-1));
            return SectionBuilderMap{};
        }
        m_section_sizes[cur_shndx] = section_header.sh_size;

        switch (section_header.sh_type) {
        case SHT_REL: {
            auto &builder = section_builders[section_header.sh_info];
            builder.set_reloc_section(cur_shndx);

            Elf_Data *data = nullptr;
            while ((data = elf_getdata(cur_section, data)) != nullptr) {
                GElf_Rel relocation;
                for (unsigned i = 0; gelf_getrel(data, i, &relocation) != nullptr; ++i) {
                    // FIXME: we need to read the addends from the section
                    // contents
                    if (GELF_R_TYPE(relocation.r_info) == m_target_info->none_reloc)
                        continue; // Skip NONE relocs, they may overlap with others
                    bool rel_changed =
                        m_target_info->ops->check_rel_for_stubs(*this, &relocation, 0,
                                                                section_header.sh_info, builder);
                    if (rel_changed) {
                        gelf_update_rel(data, i, &relocation);
                        elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
                    }
                    auto symbol_idx = GELF_R_SYM(relocation.r_info);
                    auto symbol_ref = symbol_table->get_input_symbol_ref(symbol_idx);
                    builder.set_object(this);
                    builder.mark_relocation(relocation.r_offset, GELF_R_TYPE(relocation.r_info),
                                            symbol_ref);
                }
            }
            break;
        }
        case SHT_RELA: {
            auto &builder = section_builders[section_header.sh_info];
            builder.set_reloc_section(cur_shndx);

            Elf_Data *data = nullptr;
            while ((data = elf_getdata(cur_section, data)) != nullptr) {
                GElf_Rela relocation;
                for (unsigned i = 0; gelf_getrela(data, i, &relocation) != nullptr; ++i) {
                    if (GELF_R_TYPE(relocation.r_info) == m_target_info->none_reloc)
                        continue; // Skip NONE relocs, they may overlap with others
                    bool rel_changed =
                        m_target_info->ops->check_rela_for_stubs(*this, &relocation, relocation.r_addend,
                                                                 section_header.sh_info, builder);
                    if (rel_changed) {
                        gelf_update_rela(data, i, &relocation);
                        elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
                    }
                    auto symbol_idx = GELF_R_SYM(relocation.r_info);
                    auto symbol_ref = symbol_table->get_input_symbol_ref(symbol_idx);
                    builder.set_object(this);
                    builder.mark_relocation(relocation.r_offset, GELF_R_TYPE(relocation.r_info),
                                            symbol_ref, relocation.r_addend);
                }
            }
            break;
        }
        case SHT_SYMTAB: {
            size_t sym_idx = 0;
            Elf_Data *data = nullptr;
            while ((data = elf_getdata(cur_section, data)) != nullptr) {
                GElf_Sym symbol;
                for (unsigned i = 0; gelf_getsym(data, i, &symbol) != nullptr; ++i, ++sym_idx) {
                    uint32_t sym_shndx = symbol_table->xindex_table().translate_shndx(sym_idx, symbol.st_shndx);
                    if (sym_shndx == 0 || sym_shndx >= m_num_sections)
                        continue;

                    // FIXME: if we have multiple Elf_Data structures
                    // per single SHT_SYMTAB section, then
                    // are the 'i' symbol indices correct???
                    auto sym_ref = symbol_table->get_input_symbol_ref(sym_idx);
                    switch (GELF_ST_TYPE(symbol.st_info)) {
                    case STT_FUNC:
                    case STT_ARM_TFUNC: // Marks Thumb functions on ARM
                        // FIXME: we should figure out what happens
                        // if we get STT_ARM_TFUNC on a non-ARM architecture
                        //
                        //section_builders[sym_shndx]
                        //    .mark_symbol(symbol.st_value, i, 1, symbol.st_size);
                        section_builders[sym_shndx].set_has_func_symbols();
                        if (needs_trampoline(symbol)) {
                            // needs an entry trampoline
                            section_builders[sym_shndx].add_entry_symbol(sym_ref);
                        }
                    // Fall-through
                    case STT_NOTYPE:
                    case STT_OBJECT:
                    case STT_SECTION:
                        if (symbol.st_value == 0 &&
                            GELF_ST_BIND(symbol.st_info) != STB_WEAK &&
                            symbol.st_other != STV_PROTECTED) {
                            // Symbol marks start of section
                            section_builders[sym_shndx].set_section_symbol(sym_ref);
                        }
                        break;
                    case STT_GNU_IFUNC:
                        section_builders[sym_shndx].set_has_func_symbols();
                        section_builders[sym_shndx].add_entry_symbol(sym_ref);
                        break;
                    }
                }
            }
            break;
        }
        case SHT_GROUP: {
            Elf_Data *data = nullptr;
            std::vector<Elf32_Word> group_header;
            while ((data = elf_getdata(cur_section, data)) != nullptr) {
                for (Elf32_Word *p   = reinterpret_cast<Elf32_Word*>(data->d_buf),
                                *end = reinterpret_cast<Elf32_Word*>(
                                    reinterpret_cast<char*>(data->d_buf) + data->d_size);
                     p < end; p++)
                    group_header.push_back(*p);
            }
            if (group_header[0] == GRP_COMDAT) {
                // We have a COMDAT group
                // FIXME: handle other groups later
                for (size_t i = 1; i < group_header.size(); i++)
                   section_builders[group_header[i]].set_group_section(cur_shndx);
            }
            break;
        }
        case SHT_PROGBITS:
            if (get_section_name(cur_section).compare(0, 8, ".txtrp") == 0) {
                // Error::printf("This object already contains trap info in section %s\n", get_section_name(cur_section).c_str());
                return SectionBuilderMap{};
            }
            section_builders[cur_shndx].set_section_p2align(ffs(section_header.sh_addralign) - 1);
            break;
        }
    }
    return section_builders;
}

void ElfObject::prune_section_builders(ElfObject::SectionBuilderMap *section_builders,
                                       bool emit_eh_txtrp) {
    // Iterate over the section builders to eliminate the builders
    // that aren't getting trap info.
    for (auto I = section_builders->begin(), E = section_builders->end();
         I != E; ) {
        auto section_ndx = I->first;
        auto &builder = I->second;

        if (builder.can_ignore_section()) {
            I = section_builders->erase(I);
            continue;
        }

        // If this is not a SHF_ALLOC section, ignore it
        auto *cur_section = elf_getscn(m_elf, section_ndx);
        GElf_Shdr header;
        if (!gelf_getshdr(cur_section, &header)) {
            Debug::printf<6>("Section index: %d\n", section_ndx);
            Error::printf("Error getting new section header: %s\n", elf_errmsg(-1));
        }
        if ((header.sh_flags & SHF_ALLOC) == 0) {
            Debug::printf<10>("Skipping non-ALLOC section %d\n", section_ndx);
            I = section_builders->erase(I);
            continue;
        }
        auto section_name = m_section_header_strings->get_string(header.sh_name);
        if (section_name == ".eh_frame" && !emit_eh_txtrp) {
            // Ignore .eh_frame section (for now), since it contains relocs
            // that point into potentially discarded sections, which the linker
            // doesn't like
            // FIXME: we don't actually want to do this
            Debug::printf<10>("Skipping .eh_frame section %d\n", section_ndx);
            I = section_builders->erase(I);
            continue;
        }
        if (header.sh_type == SHT_ARM_EXIDX && !emit_eh_txtrp) {
            Debug::printf<10>("Skipping .ARM.exidx section %d\n", section_ndx);
            I = section_builders->erase(I);
            continue;
        }
        if (m_target_info->trap_platform == TRAP_PLATFORM_POSIX_X86 &&
            is_gnu_linkonce(section_name)) {
            Debug::printf<10>("Skipping .gnu.linkonce... section %d\n", section_ndx);
            I = section_builders->erase(I);
            continue;

        }
        ++I;
    }
}

bool ElfObject::create_trap_info_impl(bool emit_textramp, bool emit_eh_txtrp) {
    Debug::printf<5>("Creating trap info\n");

    ElfSymbolTable symbol_table(m_elf, *this);
    if (symbol_table.empty()) {
        Debug::printf<2>("Did not find a symbol table, quitting early\n");
        return false;
    }

    auto section_builders = create_section_builders(&symbol_table);
    prune_section_builders(&section_builders, emit_eh_txtrp);
    if (section_builders.empty()) {
        Debug::printf<2>("Did not find any interesting sections, quitting early\n");
        return false;
    }

    for (auto &I : section_builders) {
        auto section_ndx = I.first;
        auto &builder = I.second;

        // Set m_object if we haven't already
        builder.set_object(this);

        auto cur_section = elf_getscn(m_elf, section_ndx);
        GElf_Shdr header;
        if (!gelf_getshdr(cur_section, &header))
            Error::printf("Error getting new section header: %s\n", elf_errmsg(-1));

        // If the architecture has a minimum alignment, set it here
        if (builder.section_p2align() < m_target_info->min_p2align)
            builder.set_section_p2align(m_target_info->min_p2align);

        // Make sure that each section has at least one TRaP symbol
        if (builder.symbols_empty()) {
            if (!builder.section_symbol().is_valid()) {
                auto new_section_symbol = symbol_table.add_section_symbol(section_ndx);
                Debug::printf<6>("%d is new section symbol for section %d\n",
                                 new_section_symbol, section_ndx);
                builder.set_section_symbol(new_section_symbol, true);
            }
            builder.mark_symbol(0, builder.section_symbol(),
                                builder.section_p2align(), 0);
        }

        // Mark and add padding
        auto name = get_section_name(cur_section);
        builder.mark_padding_offset(m_section_sizes[section_ndx]);
        if ((header.sh_flags & SHF_EXECINSTR) != 0 && is_text_section(name, false)) {
            // Add padding to .text
            size_t final_padding_size = (1 << builder.section_p2align()) - 1;
            if (final_padding_size < 4)
                final_padding_size = 4;
            // Align final_padding_size to 2^PADDING_P2ALIGN
            final_padding_size = (final_padding_size + (1 << m_target_info->padding_p2align) - 1) &
                                 -(1LL << m_target_info->padding_p2align);

            size_t curr_padding_size = 0;
            uint32_t padding = 0;
            while ((curr_padding_size + sizeof(padding)) <= final_padding_size) {
                // FIXME: make padding size variable
                add_data(cur_section, &padding, sizeof(padding), 1);
                curr_padding_size += sizeof(padding);
            }
            if (curr_padding_size < final_padding_size)
                add_data(cur_section, &padding, final_padding_size - curr_padding_size, 1);
            builder.mark_padding_size(final_padding_size);
        }

        // Build trampolines for this section
        Elf_SectionIndex tramp_section_ndx = 0;
        if (emit_textramp) {
            auto tramp_builder = m_target_info->ops->get_trampoline_builder(*this, symbol_table);
            ElfSymbolTable::SymbolMapping symbol_mapping; 
            std::tie(tramp_section_ndx, symbol_mapping) =
                tramp_builder->build_trampolines(builder.entry_symbols());
            builder.update_symbol_indices(symbol_mapping);
        }

        // Compute relocation addends
        builder.read_reloc_addends(*this, cur_section);
        builder.build_trap_data(symbol_table);

        // Add a txtrp section
        GElf_Shdr trap_section_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        trap_section_header.sh_type = SHT_PROGBITS;
        trap_section_header.sh_flags = SHF_ALLOC;
#if 0 // Disabled for now (breaks build)
        trap_section_header.sh_flags |= SHF_INFO_LINK;
        trap_section_header.sh_info = section_ndx; // For debugging
#endif
        if (builder.in_group())
            trap_section_header.sh_flags |= SHF_GROUP;

        int trap_section_ndx = add_section(".txtrp", &trap_section_header,
                                           DataBuffer(builder.get_trap_data(), 1));
        auto trap_section_symbol = symbol_table.add_section_symbol(trap_section_ndx);

        bool fake_init_anchor = false;
        if (is_ctors_section(name)) {
            // We need to implement a small hack to get around a restriction
            // in ld.bfd: .ctors/.dtors can only have exactly as many
            // relocations as words inside (one relocation per pointer),
            // so we can't add our anchor relocation directly there;
            // instead, we create a corresponding .init section and put the
            // anchor there, which is fine from a GC point since both .init
            // and .ctors/.dtors are gc roots
            fake_init_anchor = true;
#if 0 // Disabled, we just skip this section altogether
        } else if (m_target_info->trap_platform == TRAP_PLATFORM_POSIX_X86 &&
                   is_linkonce_x86_pic_thunk(name)) {
            // On 32-bit x86, crti.o contains a .gnu.linkonce.t section used
            // for PIC (see issue #54). We rely on that section being
            // discarded, but we still add a .txtrp section for it and count
            // on the linker keeping it. To make sure that happens, we add
            // the anchor reloc in .init here, instead of the discarded
            // section.
            fake_init_anchor = true;
#endif
        }
        if (fake_init_anchor) {
            GElf_Shdr fake_init_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            fake_init_header.sh_type = SHT_PROGBITS;
            fake_init_header.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            uint8_t nop = 0x90;
            int fake_init_section_ndx = add_section(".init",
                                                    &fake_init_header,
                                                    DataBuffer(&nop, 1, 1));
            add_anchor_reloc(&fake_init_header,
                             fake_init_section_ndx,
                             symbol_table.section_index(),
                             trap_section_symbol,
                             builder.symbols_size());
        } else {
            add_anchor_reloc(&header,
                             section_ndx,
                             symbol_table.section_index(),
                             trap_section_symbol,
                             builder.symbols_size());
        }

        // Add a reloc section for the txtrp
        auto &trap_relocs = builder.get_trap_reloc_data();
        assert(!trap_relocs.empty() && "No relocations inside TRaP info");
        add_section_relocs(trap_section_ndx, trap_relocs);

        // FIXME: if we create a new group, it should go at the beginning of
        // the file
        if (builder.in_group()) {
            // Add the .txtrp section to the group
            // FIXME: do we need to add the reloc section too???
            auto group_shndx = builder.group_section_ndx();
            Debug::printf<10>("Adding %d to group section %d\n",
                              trap_section_ndx, group_shndx);
            std::vector<int32_t> group_elems = { trap_section_ndx };
            if (tramp_section_ndx != 0)
                group_elems.push_back(tramp_section_ndx);
            // FIXME: what ELF_T_xxx is a SHT_GROUP section???
            add_data(group_shndx, reinterpret_cast<void*>(group_elems.data()),
                     sizeof(int32_t) * group_elems.size(), 1);
        }
    }

    Debug::printf<10>("Added .txtrp section(s)\n");
    symbol_table.mark_entry_symbol(m_entry_points.first, "_TRaP_orig_init");
    symbol_table.mark_entry_symbol(m_entry_points.second, "_TRaP_orig_entry");
    symbol_table.finalize();

    // Now add relocations
    for (auto &sec_relocs : m_section_relocs) {
        auto section_index = sec_relocs.first;
        auto &rel_buf = sec_relocs.second;
        auto it = section_builders.find(section_index);
        if (it != section_builders.end() &&
            it->second.reloc_section_ndx() != 0) {
            m_target_info->ops->add_relocs_to_section(*this, it->second.reloc_section_ndx(), rel_buf);
        } else {
            Elf_Scn *section = elf_getscn(m_elf, section_index);
            m_target_info->ops->create_reloc_section(*this,
                                                     get_section_name(section),
                                                     section_index,
                                                     symbol_table.section_index(),
                                                      rel_buf);
        }
    }

    return true;
}

void ElfObject::add_anchor_reloc(const GElf_Shdr *header,
                                 Elf_SectionIndex section_ndx,
                                 Elf_SectionIndex symtab_section_ndx,
                                 ElfSymbolTable::SymbolRef section_symbol,
                                 size_t function_count) {
    GElf_Addr reloc_offset = (header->sh_size == 0) ? 0 : (header->sh_size - 1);
    ElfReloc reloc(reloc_offset, m_target_info->none_reloc, section_symbol, 0);
    m_target_info->ops->add_reloc_to_buffer(m_section_relocs[section_ndx], &reloc);
}

ElfStringTablePtr ElfObject::get_string_table(Elf_SectionIndex section_index) {
    auto I = m_string_tables.find(section_index);
    if (I != m_string_tables.end())
        return I->second;

    Elf_Scn *section = elf_getscn(m_elf, section_index);
    auto st = std::make_shared<ElfStringTable>(section);
    m_string_tables.emplace(section_index, st);
    return st;
}

unsigned ElfObject::add_section(std::string name,
                                GElf_Shdr *header,
                                DataBuffer buffer,
                                Elf_Type data_type) {
    assert(buffer.size > 0 && "Adding empty data buffer");
    // Add a section name
    header->sh_name = m_section_header_strings->add_string(name);

    Elf_Scn *section = elf_newscn(m_elf);

    // store the data until after the file is written to disk
    m_data_buffers.push_back(buffer);
    Elf_Data *elf_data = elf_newdata(section);
    elf_data->d_buf = buffer.get();
    elf_data->d_size = buffer.size;
    elf_data->d_align = buffer.align;
    elf_data->d_type = data_type;

    if (!gelf_update_shdr(section, header))
        Error::printf("Error writing new section header: %s\n", elf_errmsg(-1));
    elf_flagshdr(section, ELF_C_SET, ELF_F_DIRTY);

    return m_num_sections++;
}

bool ElfObject::add_int32_section_patch(uint32_t shndx, Elf_Offset offset,
                                        uint32_t mask, uint32_t value) {
    auto &pair = m_section_patches[shndx][offset];
    pair.first |= mask;
    pair.second &= ~mask;
    pair.second |= (value & mask);
    return true;
}

Elf_Offset ElfObject::add_data(uint32_t shndx, void* data, size_t size, unsigned align,
                              Elf_Type data_type) {
    assert(size > 0 && "Adding empty data buffer");
    Debug::printf<10>("Adding new data to section %u\n", shndx);

    DataBuffer buffer(data, size, align);
    m_data_buffers.push_back(buffer);

    Elf_Scn *section = elf_getscn(m_elf, shndx);
    Elf_Data *new_data = elf_newdata(section);
    new_data->d_size = size;
    new_data->d_buf = buffer.get();
    new_data->d_align = align;
    new_data->d_type = data_type;
    elf_flagdata(new_data, ELF_C_SET, ELF_F_DIRTY);

    // Update the section sizes
    Elf_Offset &section_size = m_section_sizes[shndx];
    Elf_Offset this_off = section_size;
    auto rem = this_off % align;
    if (rem > 0)
        this_off += align - rem;
    section_size = this_off + size;

    // This will actually be controlled by libelf when it write the file since
    // it does layout, but we need this to be correct in the mean time
    new_data->d_off = this_off;

    return this_off;
}

void ElfObject::replace_data(Elf_Scn *section, DataBuffer buffer) {
    Debug::printf<10>("Replacing data in section %u\n", elf_ndxscn(section));
    Elf_Data *elf_data = elf_getdata(section, nullptr);
    assert(elf_data->d_off == 0 && "Bad section data replacement");
    m_data_buffers.push_back(buffer);
    elf_data->d_buf = buffer.get();
    elf_data->d_size = buffer.size;
    elf_data->d_align = buffer.align;
    elf_flagdata(elf_data, ELF_C_SET, ELF_F_DIRTY);

    // Zero out other datas
    while ((elf_data = elf_getdata(section, elf_data)) != nullptr) {
        elf_data->d_buf = nullptr;
        elf_data->d_size = 0;
        elf_flagdata(elf_data, ELF_C_SET, ELF_F_DIRTY);
    }
}

bool ElfObject::update_archive(const std::string &original_ar_path,
                               std::vector<std::string> object_files,
                               std::string archive_filename) {
    std::vector<char*> ar_invocation;

    const char *ar_path;
    if (!original_ar_path.empty()) {
        ar_path = original_ar_path.c_str();
    } else if ((ar_path = getenv(kArPathVariable)) == nullptr) {
        ar_path = "ar";
    }
    ar_invocation.push_back(strdup(ar_path));
    ar_invocation.push_back(strdup("r"));
    ar_invocation.push_back(strdup(archive_filename.c_str()));

    for (auto file : object_files) {
        ar_invocation.push_back(strdup(file.c_str()));
    }

    for (auto s : ar_invocation) {
        Debug::printf<6>("%s ", s);
    }
    Debug::printf<6>("\n");

    ar_invocation.push_back(nullptr);

    if (!Misc::exec_child(ar_invocation.data(), nullptr, true))
        Error::printf("Could not exec ar\n");

    // free dup'ed strings
    for (auto s : ar_invocation)
        free(s);

    return true;
}

bool ElfObject::update_file() {
    if (!m_parsed)
        return false;

    Debug::printf<10>("Updating .shstrtab\n");
    m_section_header_strings->update(*this);

    for (auto &new_section_info : m_new_sections) {
        Elf_Scn *section = elf_newscn(m_elf);
        GElf_Shdr header;
        if (!gelf_getshdr(section, &header))
            Error::printf("Error getting new section header: %s\n", elf_errmsg(-1));

        header.sh_name = new_section_info.first.sh_name;
        Debug::printf<10>("Section name: %u\n", header.sh_name);
        header.sh_type = new_section_info.first.sh_type;
        header.sh_flags = new_section_info.first.sh_flags;
        header.sh_link = new_section_info.first.sh_link;
        header.sh_info = new_section_info.first.sh_info;
        header.sh_addralign = new_section_info.first.sh_addralign;
        header.sh_entsize = new_section_info.first.sh_entsize;
        header.sh_size = new_section_info.second.size;

        Elf_Data *data = elf_newdata(section);
        data->d_buf = new_section_info.second.buffer.get();
        data->d_size = new_section_info.second.size;
        data->d_align = new_section_info.second.align;

        if (!gelf_update_shdr(section, &header))
            Error::printf("Error writing new section header: %s\n", elf_errmsg(-1));
        elf_flagshdr(section, ELF_C_SET, ELF_F_DIRTY);
    }

    // Iterate through all sections and their patches
    // and apply the later in batches (grouped by ELF data)
    for (auto &patched_section : m_section_patches) {
        Elf_Scn *sec = elf_getscn(m_elf, patched_section.first);
        Elf_Data *data = nullptr;
        while ((data = elf_getdata(sec, data)) != nullptr) {
            decltype(patched_section.second)::iterator it, end;
            it  = patched_section.second.lower_bound(data->d_off);
            end = patched_section.second.lower_bound(data->d_off + data->d_size);
            if (it != end)
                elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
            for (; it != end; it++) {
                auto i8_ptr = reinterpret_cast<uint8_t*>(data->d_buf);
                i8_ptr += it->first - data->d_off;
                auto i32_ptr = reinterpret_cast<uint32_t*>(i8_ptr);
                *i32_ptr &= ~it->second.first;
                *i32_ptr |= (it->second.second & it->second.first);
            }
        }
    }

    if (elf_update(m_elf, ELF_C_WRITE) == -1) {
        Error::printf("Error writing modified ELF file to disk (after adding new data): %s\n", elf_errmsg(-1));
        return false;
    }

    m_new_sections.clear();
    m_section_sizes.clear();
    m_section_patches.clear();
    m_section_relocs.clear();

    return true;
}

Elf* ElfObject::write_new_file(int fd) {
    Elf *new_elf = elf_begin(fd, ELF_C_WRITE, nullptr);
    if (!new_elf)
        Error::printf("Could not create ELF handle: %s\n", elf_errmsg(-1));

    int elf_class = gelf_getclass(m_elf);
    if (!elf_class)
        Error::printf("Could not get ELF class: %s\n", elf_errmsg(-1));

    if (!gelf_newehdr(new_elf, elf_class))
        Error::printf("Could not create new ELF header for archive member copy: %s\n", elf_errmsg(-1));

    GElf_Ehdr ehdr;
    if (!gelf_update_ehdr(new_elf, gelf_getehdr(m_elf, &ehdr)))
        Error::printf("Could not copy ELF header for archive member copy: %s\n", elf_errmsg(-1));

    if (ehdr.e_phnum > 0) {
        size_t num_phdr;
        if (!elf_getphdrnum(m_elf, &num_phdr))
            Error::printf("Could not read number of program headers for archive member copy: %s\n", elf_errmsg(-1));

        if (!gelf_newphdr(new_elf, num_phdr))
            Error::printf("Could not create new program header for archive member copy: %s", elf_errmsg(-1));

        for (size_t i = 0; i < num_phdr; ++i) {
            GElf_Phdr phdr;
            if (!gelf_update_phdr(new_elf, i, gelf_getphdr(m_elf, i, &phdr)))
                Error::printf("Could not copy ELF header for archive member copy: %s\n", elf_errmsg(-1));
        }
    }

    Elf_Scn *old_section = nullptr;
    while ((old_section = elf_nextscn(m_elf, old_section)) != nullptr) {
        Elf_Scn *new_section = elf_newscn(new_elf);
        if (!new_section)
            Error::printf("Could not create new section for archive member copy: %s\n", elf_errmsg(-1));

        GElf_Shdr shdr;
        if (!gelf_update_shdr(new_section, gelf_getshdr(old_section, &shdr)))
            Error::printf("Could not copy section header for archive member copy: %s\n", elf_errmsg(-1));
        Debug::printf<10>("Copied entity size: %u\n", shdr.sh_entsize);
        Debug::printf<10>("Copied section size: %u\n", shdr.sh_size);

        Elf_Data *old_data = nullptr;
        while ((old_data = elf_getdata(old_section, old_data)) != nullptr) {
            Elf_Data *new_data = elf_newdata(new_section);
            if (!new_data)
                Error::printf("Could not copy section data for archive member copy: %s\n", elf_errmsg(-1));
            *new_data = *old_data;
        }
    }

    if (elf_update(new_elf, ELF_C_WRITE) == -1) {
        Error::printf("Error writing modified ELF file to disk: %s\n", elf_errmsg(-1));
    }

    return new_elf;
}

void* ElfObject::data() {
    return nullptr;
}

ElfObject::~ElfObject() {
    if (m_elf)
        elf_end(m_elf);
}

bool ElfObject::has_copy_relocs(const char *filename) {
    bool found_copy_relocs = false;
    int fd;
    Elf *elf;
    Elf_Scn *cur_section = nullptr;
    GElf_Ehdr ehdr;
    const TargetInfo *target_info;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        Error::printf("Could not open output file: %s\n", filename);
        goto ret;
    }

    elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (elf == nullptr) {
        Error::printf("Could not open output file: %s\n", filename);
        goto close_file;
    }
    if (elf_kind(elf) != ELF_K_ELF) {
        Error::printf("Output file not ELF: %s\n", filename);
        goto close_elf;
    }
    if (gelf_getehdr(elf, &ehdr) == nullptr) {
        Error::printf("Could not get ELF header: %s\n", elf_errmsg(-1));
        goto close_elf;
    }
    target_info = &kInfoForTargets.at(ehdr.e_machine);

    // Scan all relocation sections looking for R_xxx_COPY relocs
    while (!found_copy_relocs &&
           (cur_section = elf_nextscn(elf, cur_section)) != nullptr) {
        GElf_Shdr shdr;
        if (gelf_getshdr(cur_section, &shdr) == nullptr) {
            Error::printf("Could not parse section header: %s\n", elf_errmsg(-1));
            goto close_elf;
        }
        if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA) {
            Elf_Data *data = nullptr;
            while (!found_copy_relocs &&
                   (data = elf_getdata(cur_section, data)) != nullptr) {
                if (shdr.sh_type == SHT_REL) {
                    GElf_Rel rel;
                    for (unsigned i = 0; gelf_getrel(data, i, &rel) != nullptr; ++i) {
                        if (GELF_R_TYPE(rel.r_info) == target_info->copy_reloc) {
                            found_copy_relocs = true;
                            break;
                        }
                    }
                } else {
                    GElf_Rela rel;
                    for (unsigned i = 0; gelf_getrela(data, i, &rel) != nullptr; ++i) {
                        if (GELF_R_TYPE(rel.r_info) == target_info->copy_reloc) {
                            found_copy_relocs = true;
                            break;
                        }
                    }
                }
            }
        }
    }

close_elf:
    elf_end(elf);
close_file:
    close(fd);
ret:
    return found_copy_relocs;
}

ElfStringTable::ElfStringTable(Elf_Scn *section) {
    m_section = section;
    m_string_table.clear();
    m_indices.clear();
    m_string_index_map.clear();

    Elf_Data *data = nullptr;
    std::string input_string;
    while ((data = elf_getdata(m_section, data)) != nullptr) {
        input_string.append((char*)data->d_buf, data->d_size);
    }
    m_initial_size = m_next_index = input_string.size();
    auto sp = std::make_shared<const std::string>(std::move(input_string));
    m_string_table.emplace_back(sp);
    m_indices.push_back(0);

    // Add the string and all its suffixes to the hash map
    hash_string_suffixes(sp, 0);
}

void ElfStringTable::update(ElfObject &object) {
    if (m_next_index == m_initial_size)
        return;

    Debug::printf<10>("Updating string table...\n");

    size_t i = 0;
    while (i < m_indices.size() && m_indices[i] < m_initial_size)
        i++;
    assert(m_indices[i] == m_initial_size &&
           "Mismatch between indices vector and actual string size");
    for (; i < m_indices.size(); i++) {
        auto &str = m_string_table[i];
        auto zlen = str->size() + 1;
        object.add_data(m_section, const_cast<char*>(str->c_str()), zlen);
    }
    assert(m_indices.size() == m_string_table.size() &&
           "Mismatch between ElfStringTable vector sizes");

    // reset initial size, in case update() is called again
    m_initial_size = m_next_index;
}

ElfSymbolTable::ElfSymbolTable(Elf *elf, ElfObject &object)
    : m_finalized(false), m_section(nullptr),
      m_object(object), m_xindex_table(object) {
    find_symtab();
    read_symbols();
}

void ElfSymbolTable::find_symtab() {
    // Find and read symbol table section
    for (auto cur_section : m_object) {
        GElf_Shdr section_header;
        if (gelf_getshdr(cur_section, &section_header) == nullptr) {
            Error::printf("Could not parse section header: %s\n", elf_errmsg(-1));
            return;
        }
        if (section_header.sh_type == SHT_SYMTAB) {
            m_section = cur_section;
            m_string_table = m_object.get_string_table(section_header.sh_link);
            return;
        }
    }
}

void ElfSymbolTable::read_symbols() {
    if (m_section == nullptr)
        return;

    size_t sym_idx = 0;
    Elf_Data *data = nullptr;
    while ((data = elf_getdata(m_section, data)) != nullptr) {
        GElf_Sym symbol;
        for (unsigned i = 0; gelf_getsym(data, i, &symbol) != nullptr; ++i, ++sym_idx) {
            if (GELF_ST_BIND(symbol.st_info) == STB_LOCAL) {
                m_input_locals.push_back(symbol);
            } else {
                m_input_globals.push_back(symbol);
            }
        }
    }
}

ElfSymbolTable::SymbolRef ElfSymbolTable::replace_symbol(SymbolRef symbol,
                                                         GElf_Addr new_value,
                                                         Elf_SectionIndex section_index,
                                                         size_t new_size) {
    GElf_Sym *old_symbol = symbol.get();
    GElf_Sym new_symbol = *old_symbol;

    // Add new symbol by appending "$orig" to the original symbol name.
    auto sym_name_orig = get_suffixed_symbol(old_symbol->st_name, "$orig");
    new_symbol.st_name = m_string_table->add_string(sym_name_orig);
    new_symbol.st_other = GELF_ST_VISIBILITY(STV_HIDDEN);
    if (GELF_ST_TYPE(new_symbol.st_info) == STT_GNU_IFUNC) {
        // The externally-visible symbol should still be an ifunc,
        // but the internal ones shouldn't because we only want
        // the function to be called once
        auto binding = GELF_ST_BIND(new_symbol.st_info);
        new_symbol.st_info = GELF_ST_INFO(STT_FUNC, binding);
    }

    // Add new symbol for wrapper
    uint32_t old_sym_xindex;
    uint32_t new_sym_xindex = m_xindex_table.get(symbol.get_input_index());
    if (section_index >= SHN_LORESERVE) {
        old_symbol->st_shndx = SHN_XINDEX;
        old_sym_xindex = section_index;
    } else {
        old_symbol->st_shndx = section_index;
        old_sym_xindex = 0;
    }
    m_xindex_table.set(symbol.get_input_index(), old_sym_xindex);
    old_symbol->st_value = new_value;
    old_symbol->st_size  = new_size;
    return add_symbol(new_symbol, new_sym_xindex);
}

void ElfSymbolTable::mark_entry_symbol(std::string orig_symbol_name, std::string symbol_name) {
    auto check_symbol = [this, &orig_symbol_name, &symbol_name]
            (const GElf_Sym &symbol, uint32_t new_sym_xindex){
        if (m_string_table->get_string(symbol.st_name) == orig_symbol_name) {
            Debug::printf<3>("Marking entry point symbol: %s\n", orig_symbol_name.c_str());
            GElf_Sym new_symbol = symbol;
            new_symbol.st_name = m_string_table->add_string(symbol_name);
            new_symbol.st_info = GELF_ST_INFO(STB_WEAK, STT_FUNC);
            new_symbol.st_other = STV_HIDDEN;
            add_symbol(new_symbol, new_sym_xindex);
            return true;
        }
        return false;
    };


    size_t sym_idx = 0;
    for (auto &symbol : m_input_locals) {
        if (check_symbol(symbol, m_xindex_table.get(sym_idx)))
            return;
        sym_idx++;
    }
    for (auto &symbol : m_input_globals) {
        if (check_symbol(symbol, m_xindex_table.get(sym_idx)))
            return;
        sym_idx++;
    }
    sym_idx = 0;
    for (auto &symbol : m_new_locals) {
        if (check_symbol(symbol, m_new_locals_xindex[sym_idx]))
            return;
        sym_idx++;
    }
    sym_idx = 0;
    for (auto &symbol : m_new_globals) {
        if (check_symbol(symbol, m_new_globals_xindex[sym_idx]))
            return;
        sym_idx++;
    }
}

ElfSymbolTable::SymbolRef
ElfSymbolTable::add_local_symbol(GElf_Addr address,
                                 Elf_SectionIndex section_index,
                                 const std::string &name,
                                 uint8_t type, size_t size) {
    GElf_Sym symbol;
    uint32_t xindex;
    symbol.st_name = m_string_table->add_string(name);
    symbol.st_info = GELF_ST_INFO(STB_LOCAL, type);
    symbol.st_other = STV_DEFAULT;
    if (section_index >= SHN_LORESERVE) {
        symbol.st_shndx = SHN_XINDEX;
        xindex = section_index;
    } else {
        symbol.st_shndx = section_index;
        xindex = 0;
    }
    symbol.st_value = address;
    symbol.st_size = size;
    return add_symbol(symbol, xindex);
}

ElfSymbolTable::SymbolRef ElfSymbolTable::add_section_symbol(Elf_SectionIndex section_index) {
    GElf_Sym symbol;
    uint32_t xindex;
    symbol.st_name = 0;
    symbol.st_info = GELF_ST_INFO(STB_LOCAL, STT_SECTION);
    symbol.st_other = STV_DEFAULT;
    if (section_index >= SHN_LORESERVE) {
        symbol.st_shndx = SHN_XINDEX;
        xindex = section_index;
    } else {
        symbol.st_shndx = section_index;
        xindex = 0;
    }
    symbol.st_value = 0;
    symbol.st_size = 0;
    return add_symbol(symbol, xindex);
}

ElfSymbolTable::SymbolRef ElfSymbolTable::add_symbol(GElf_Sym symbol, uint32_t xindex) {
    assert(!m_finalized && "Attempted to add new symbol to finalized symbol table");
    if (GELF_ST_BIND(symbol.st_info) == STB_LOCAL) {
        m_new_locals.push_back(symbol);
        m_new_locals_xindex.push_back(xindex);
        return SymbolRef(this, SymbolRef::NEW_LOCAL, m_new_locals.size() - 1);
    } else {
        m_new_globals.push_back(symbol);
        m_new_globals_xindex.push_back(xindex);
        return SymbolRef(this, SymbolRef::NEW_GLOBAL, m_new_globals.size() - 1);
    }
}


void ElfSymbolTable::finalize() {
    assert(!m_finalized && "Attempted to finalize symbol table multiple times");
    m_finalized = true;

    m_string_table->update(m_object);

    if (m_new_locals.empty() &&
        m_new_globals.empty())
        return;

    std::vector<uint8_t> new_data;
    for (auto &sym : m_input_locals)
        add_target_symbol(&new_data, sym);
    for (auto &sym : m_new_locals)
        add_target_symbol(&new_data, sym);
    for (auto &sym : m_input_globals)
        add_target_symbol(&new_data, sym);
    for (auto &sym : m_new_globals)
        add_target_symbol(&new_data, sym);
    m_object.replace_data(m_section, ElfObject::DataBuffer(new_data, 1));

    size_t num_new_locals = m_new_locals.size();
    if (num_new_locals > 0) {
        update_symbol_references();

        // Update the xindex table
        assert(m_new_locals_xindex.size() == num_new_locals && "Invalid new xindex size");
        m_xindex_table.add_new(m_input_locals.size(), m_new_locals_xindex);

        GElf_Shdr symtab_section_header;
        if (!gelf_getshdr(m_section, &symtab_section_header))
            Error::printf("Could not get symtab section header. Error %s\n", elf_errmsg(-1));

        // We added new locals, so we need to increment the start of the globals
        assert(symtab_section_header.sh_info == m_input_locals.size() &&
               "Invalid local symbol count");
        symtab_section_header.sh_info += num_new_locals;

        if (!gelf_update_shdr(m_section, &symtab_section_header))
            Error::printf("Could not update symtab section header. Error %s\n", elf_errmsg(-1));
        elf_flagshdr(m_section, ELF_C_SET, ELF_F_DIRTY);
    }

    assert(m_new_globals_xindex.size() == m_new_globals.size() && "Invalid new xindex size");
    m_xindex_table.add_new(m_input_locals.size() + num_new_locals + m_input_globals.size(), m_new_globals_xindex);
    m_xindex_table.update();
#if 0
    // Update the internal arrays with the new symbols
    // FIXME: we shouldn't actually need to do this
    m_input_locals.insert(m_input_locals.end(),
                          m_new_locals.begin(),
                          m_new_locals.end());
    m_input_globals.insert(m_input_globals.end(),
                           m_new_globals.begin(),
                           m_new_globals.end());

    // Clear all new buffers
    m_new_locals.clear();
    m_new_globals.clear();
    m_new_locals_xindex.clear();
    m_new_globals_xindex.clear();
#endif
}

void ElfSymbolTable::update_symbol_references() {
    for (auto section : m_object) {
        GElf_Shdr header;
        if (gelf_getshdr(section, &header) == nullptr) {
            Error::printf("Could not parse section header: %s\n", elf_errmsg(-1));
        }

        Debug::printf<4>("Parsing section index %u to update relocs\n", elf_ndxscn(section));

        switch (header.sh_type) {
        case SHT_REL: {
            Elf_Data *data = nullptr;
            while ((data = elf_getdata(section, data)) != nullptr) {
                GElf_Rel relocation;
                for (unsigned i = 0; gelf_getrel(data, i, &relocation) != nullptr; ++i) {
                    Debug::printf<4>("Found relocation to check\n");
                    uint32_t symbol_index = GELF_R_SYM(relocation.r_info);
                    auto symbol_ref = get_input_symbol_ref(symbol_index);
                    auto final_index = symbol_ref.get_final_index();
                    if (final_index != symbol_index) {
                        Debug::printf<4>("Updating to %u in global reloc for symbol %u\n",
                                         final_index, symbol_index);
                        relocation.r_info = GELF_R_INFO(final_index,
                                                        GELF_R_TYPE(relocation.r_info));
                        gelf_update_rel(data, i, &relocation);
                        elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
                    }
                }
            }
            break;
        }
        case SHT_RELA: {
            Elf_Data *data = nullptr;
            while ((data = elf_getdata(section, data)) != nullptr) {
                GElf_Rela relocation;
                for (unsigned i = 0; gelf_getrela(data, i, &relocation) != nullptr; ++i) {
                    Debug::printf<4>("Found relocation to check\n");
                    uint32_t symbol_index = GELF_R_SYM(relocation.r_info);
                    auto symbol_ref = get_input_symbol_ref(symbol_index);
                    auto final_index = symbol_ref.get_final_index();
                    if (final_index != symbol_index) {
                        Debug::printf<4>("Updating to %u in global reloc for symbol %u\n",
                                         final_index, symbol_index);
                        relocation.r_info = GELF_R_INFO(final_index,
                                                        GELF_R_TYPE(relocation.r_info));
                        gelf_update_rela(data, i, &relocation);
                        elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
                    }
                }
            }
            break;
        }
        case SHT_GROUP: {
            auto symbol_ref = get_input_symbol_ref(header.sh_info);
            auto final_index = symbol_ref.get_final_index();
            if (final_index != header.sh_info) {
                header.sh_info = final_index;
                gelf_update_shdr(section, &header);
                elf_flagshdr(section, ELF_C_SET, ELF_F_DIRTY);
            }
            break;
        }
        }
    }
}

void ElfSymbolTable::add_target_symbol(std::vector<uint8_t> *buf,
                                       const GElf_Sym &sym) {
    if (m_object.get_target_info()->addr_size == 32) {
        Elf32_Sym new_sym;
        new_sym.st_name = sym.st_name;
        new_sym.st_value = sym.st_value;
        new_sym.st_size = sym.st_size;
        new_sym.st_info = sym.st_info;
        new_sym.st_other = sym.st_other;
        new_sym.st_shndx = sym.st_shndx;
        auto new_sym_buf = reinterpret_cast<uint8_t*>(&new_sym);
        buf->insert(buf->end(),
                    new_sym_buf,
                    new_sym_buf + sizeof(new_sym));
    } else {
        Elf64_Sym new_sym;
        new_sym.st_name = sym.st_name;
        new_sym.st_value = sym.st_value;
        new_sym.st_size = sym.st_size;
        new_sym.st_info = sym.st_info;
        new_sym.st_other = sym.st_other;
        new_sym.st_shndx = sym.st_shndx;
        auto new_sym_buf = reinterpret_cast<uint8_t*>(&new_sym);
        buf->insert(buf->end(),
                    new_sym_buf,
                    new_sym_buf + sizeof(new_sym));
     }
}


ElfSymbolTable::XindexTable::XindexTable(ElfObject &object)
    : m_object(object), m_section(nullptr), m_symtab_index(0) {
    for (auto cur_section : object) {
        GElf_Shdr section_header;
        if (gelf_getshdr(cur_section, &section_header) == nullptr) {
            Error::printf("Could not parse section header: %s\n", elf_errmsg(-1));
            return;
        }
        switch (section_header.sh_type) {
        case SHT_SYMTAB: {
            auto new_symtab_index = elf_ndxscn(cur_section);
            assert((m_symtab_index == 0 || m_symtab_index == new_symtab_index) &&
                   "Index mismatch between .symtab and .symtab_shndx");
            m_symtab_index = new_symtab_index;

            size_t num_symbols = section_header.sh_size / section_header.sh_entsize;
            if (num_symbols > m_xindex_table.size())
                m_xindex_table.resize(num_symbols);
            break;
        }
        case SHT_SYMTAB_SHNDX: {
            m_section = cur_section;

            auto new_symtab_index = section_header.sh_link;
            assert((m_symtab_index == 0 || m_symtab_index == new_symtab_index) &&
                   "Index mismatch between .symtab and .symtab_shndx");
            m_symtab_index = new_symtab_index;

            Elf_Data *data = nullptr;
            size_t idx = 0;
            while ((data = elf_getdata(cur_section, data)) != nullptr) {
                size_t new_elems = data->d_size / sizeof(uint32_t);
                if (idx + new_elems > m_xindex_table.size())
                    m_xindex_table.resize(idx + new_elems);
                for (Elf32_Word *p   = reinterpret_cast<Elf32_Word*>(data->d_buf),
                                *end = reinterpret_cast<Elf32_Word*>(
                                    reinterpret_cast<char*>(data->d_buf) + data->d_size);
                     p < end; p++, idx++)
                    m_xindex_table[idx] = *p;
            }
            break;
        }
        }
    }
}

void ElfSymbolTable::XindexTable::add_new(size_t where,
                                          const std::vector<uint32_t> &new_entries) {
    m_xindex_table.insert(m_xindex_table.begin() + where,
                          new_entries.begin(), new_entries.end());
}

void ElfSymbolTable::XindexTable::update() {
    if (m_section == nullptr) {
        // No section in file
        // First we check if we need to create one; if not, we stop
        auto non_zero = std::find_if(m_xindex_table.begin(), m_xindex_table.end(),
                                     [] (const uint32_t v) { return v != 0; });
        if (non_zero == m_xindex_table.end())
            return; // Table is empty, no need to do anything

        GElf_Shdr xindex_section_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        xindex_section_header.sh_type = SHT_SYMTAB_SHNDX;
        xindex_section_header.sh_link = m_symtab_index;
        xindex_section_header.sh_entsize = sizeof(uint32_t);
        m_object.add_section(".symtab_shndx", &xindex_section_header,
                             ElfObject::DataBuffer(m_xindex_table, 4));
    } else {
        // Replace the section contents (even if all zeroes)
        m_object.replace_data(m_section, ElfObject::DataBuffer(m_xindex_table, 4));
    }
}

std::tuple<Elf_SectionIndex, ElfSymbolTable::SymbolMapping>
TrampolineBuilder::build_trampolines(const EntrySymbols &entry_symbols) {
    if (entry_symbols.empty())
        return std::make_tuple(0, ElfSymbolTable::SymbolMapping{});

    GElf_Shdr tramp_section_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    tramp_section_header.sh_type = SHT_PROGBITS;
    tramp_section_header.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    tramp_section_header.sh_addralign = 2;
    Elf_SectionIndex tramp_section_index =
        m_object.add_section(".textramp", &tramp_section_header,
                             create_trampoline_data(entry_symbols));

    ElfSymbolTable::SymbolMapping symbol_mapping;
    for (auto trampoline : m_trampoline_offsets) {
        auto old_symbol_index = trampoline.first;
        GElf_Addr tramp_offset = trampoline.second;
        auto new_symbol_index =
            m_symbol_table.replace_symbol(old_symbol_index, tramp_offset,
                                          tramp_section_index, trampoline_size());
        add_reloc(new_symbol_index, tramp_offset);
        symbol_mapping[old_symbol_index] = new_symbol_index;
    }

    // Allow target to do any special stuff to the new section
    target_postprocessing(tramp_section_index);

    if (!m_trampoline_relocs.empty())
        m_object.add_section_relocs(tramp_section_index, m_trampoline_relocs);
    return std::make_tuple(tramp_section_index, symbol_mapping);
}


void TrapRecordBuilder::mark_symbol(Elf_Offset offset, ElfSymbolTable::SymbolRef symbol,
                                    Elf_Offset p2align, size_t size) {
    m_symbols.push_back(TrapSymbol(offset, symbol, p2align, size));
}

void TrapRecordBuilder::mark_relocation(Elf_Offset offset, uint32_t type,
                                        ElfSymbolTable::SymbolRef symbol) {
    auto trap_platform = m_object->get_target_info()->trap_platform;
    auto extra_info = trap_reloc_info(type, trap_platform);
    if (extra_info & TRAP_RELOC_IGNORE)
        return;
    if (extra_info & TRAP_RELOC_ADDEND)
        m_addendless_relocs.push_back(m_relocs.size());
    m_relocs.push_back(ElfReloc(offset, type, symbol));
}

void TrapRecordBuilder::mark_relocation(Elf_Offset offset, uint32_t type,
                                        ElfSymbolTable::SymbolRef symbol,
                                        Elf_Offset addend) {
    auto trap_platform = m_object->get_target_info()->trap_platform;
    auto extra_info = trap_reloc_info(type, trap_platform);
    if (extra_info & TRAP_RELOC_IGNORE)
        return;
    m_relocs.push_back(ElfReloc(offset, type, symbol, addend));
}

void TrapRecordBuilder::mark_data_ref(Elf_Offset offset) {
    m_data_refs.push_back(offset);
}

void TrapRecordBuilder::mark_padding_offset(Elf_Offset offset) {
    m_padding_offset = offset;
}

void TrapRecordBuilder::mark_padding_size(Elf_Offset size) {
    m_padding_size = size;
}

void TrapRecordBuilder::update_symbol_indices(ElfSymbolTable::SymbolMapping &symbol_mapping) {
    for (auto &sym : m_symbols) {
        auto I = symbol_mapping.find(sym.symbol);
        if (I != symbol_mapping.end()) {
            sym.symbol = I->second;
        }
    }
}


void TrapRecordBuilder::read_reloc_addends(ElfObject &object,
                                           Elf_Scn *section) {
    if (m_addendless_relocs.empty())
        return;

    std::sort(m_addendless_relocs.begin(), m_addendless_relocs.end(),
              [this] (size_t ia, size_t ib) {
            return m_relocs[ia].offset < m_relocs[ib].offset;
        });

    auto find_cmp_fn = [this] (size_t idx, off_t offset) {
        return m_relocs[idx].offset < offset;
    };

    Elf_Data *data = nullptr;
    while ((data = elf_getdata(section, data)) != nullptr) {
        auto it = std::lower_bound(m_addendless_relocs.begin(),
                                   m_addendless_relocs.end(),
                                   data->d_off,
                                   find_cmp_fn);
        auto end = std::lower_bound(m_addendless_relocs.begin(),
                                    m_addendless_relocs.end(),
                                    data->d_off + data->d_size,
                                    find_cmp_fn);
        for (; it != end; it++) {
            auto reloc_idx = *it;
            auto &reloc = m_relocs[reloc_idx];
            auto rel_data_ofs = reloc.offset - data->d_off;
            // FIXME: size of the read should depend on the relocation
            // for now, only 32-bit x86 and ARM use these, and only for
            // full 32-bit relocations, so we're fine (for now)
            auto addend = object.get_target_info()->ops->read_reloc(
                reinterpret_cast<char*>(data->d_buf) + rel_data_ofs, reloc);
            reloc.addend = addend;
            Debug::printf<10>("Found reloc addend %d at offset %d type %d\n",
                              addend, reloc.offset, reloc.type);
        }
    }
    m_addendless_relocs.clear();
}

void TrapRecordBuilder::write_reloc(const ElfReloc &reloc, Elf_Offset prev_offset,
                                    const ElfSymbolTable &symbol_table) {
    Debug::printf<10>("Writing reloc at offset: %u\n", reloc.offset);
    // Offset
    push_back_uleb128(reloc.offset - prev_offset);
    // Type
    push_back_uleb128(reloc.type);
    Elf_Offset trap_addend = reloc.addend;
    auto trap_platform = m_object->get_target_info()->trap_platform;
    auto extra_info = trap_reloc_info(reloc.type, trap_platform);
    if (extra_info & TRAP_RELOC_SYMBOL) {
        // Symbol
        ElfReloc sym_addr_reloc(m_data.size(),
                                m_object->get_target_info()->symbol_reloc,
                                reloc.symbol.as_local(), 0);
        if (trap_addend > 0) {
            // Hack for the addend ambiguity: roll positive addends into the symbol
            // address, but put negative ones in TRaP info (gold does something similar)
            sym_addr_reloc.addend = trap_addend;
            trap_addend = 0;
        }
        m_object->get_target_info()->ops->add_reloc_to_buffer(m_reloc_data, &sym_addr_reloc);
        push_back_int(sym_addr_reloc.addend, m_object->get_target_info()->addr_size / 8);
    }
    if (extra_info & TRAP_RELOC_ADDEND) {
        // Addend
        push_back_sleb128(trap_addend);
    }
    if (extra_info & TRAP_RELOC_ARM64_GOT_PAGE) {
        // We have a special case on ARM64 for a pair of instruction
        // relocations: R_AARCH64_ADR_GOT_PAGE and R_AARCH64_LD64_GOT_LO12_NC
        // which are used together to build the address of a symbol's GOT entry
        // in the following way: R_AARCH64_ADR_GOT_PAGE stores bits 63:12 of
        // the entry in a register, then R_AARCH64_LD64_GOT_LO12_NC adds bits
        // 11:0 (the page offset) to that register and uses the resulting
        // address to load the entry. Whenever RandoLib encounters one of these
        // relocations, it also needs the other one, so we store the
        // R_AARCH64_ADR_GOT_PAGE relocation's pair as an instruction embedded
        // directly inside TRaP info as a 32-bit word.
        assert((extra_info & TRAP_RELOC_SYMBOL) == 0 && "Bad Trap relocation info");
        assert(reloc.type == R_AARCH64_ADR_GOT_PAGE);
        ElfReloc trap_reloc(m_data.size(), R_AARCH64_LD64_GOT_LO12_NC,
                            reloc.symbol, reloc.addend);
        m_object->get_target_info()->ops->add_reloc_to_buffer(m_reloc_data, &trap_reloc);
        push_back_int(0xf9400000, 4); // LDR x0, [x0]
    }
    if (extra_info & TRAP_RELOC_ARM64_GOT_GROUP) {
        // Similar handling of GOT group relocations: for every G0 relocation,
        // we add the G1-G3 relocations inline inside Trap info
        assert((extra_info & TRAP_RELOC_SYMBOL) == 0 && "Bad Trap relocation info");
        assert((extra_info & TRAP_RELOC_ADDEND) == 0 && "Bad Trap relocation info");
        assert(reloc.type == R_AARCH64_MOVW_GOTOFF_G0 ||
               reloc.type == R_AARCH64_MOVW_GOTOFF_G0_NC);
        // G1 reloc
        ElfReloc trap_reloc1(m_data.size(), R_AARCH64_MOVW_GOTOFF_G1_NC,
                             reloc.symbol, reloc.addend);
        m_object->get_target_info()->ops->add_reloc_to_buffer(m_reloc_data, &trap_reloc1);
        push_back_int(0xf2a00000, 4); // MOVK x0, 0, lsl #16
        // G2 reloc
        ElfReloc trap_reloc2(m_data.size(), R_AARCH64_MOVW_GOTOFF_G2_NC,
                             reloc.symbol, reloc.addend);
        m_object->get_target_info()->ops->add_reloc_to_buffer(m_reloc_data, &trap_reloc2);
        push_back_int(0xf2c00000, 4); // MOVK x0, 0, lsl #32
        // G3 reloc
        ElfReloc trap_reloc3(m_data.size(), R_AARCH64_MOVW_GOTOFF_G3,
                             reloc.symbol, reloc.addend);
        m_object->get_target_info()->ops->add_reloc_to_buffer(m_reloc_data, &trap_reloc3);
        push_back_int(0xd2e00000, 4); // MOVZ x0, 0, lsl #48
    }
}

void TrapRecordBuilder::build_trap_data(const ElfSymbolTable &symbol_table) {
    m_data.clear();

    if (can_ignore_section())
        return;

    assert(!m_symbols.empty() && "No symbols for section");
    std::sort(m_symbols.begin(),  m_symbols.end());

    Debug::printf<10>("Adding first trap symbol at %u\n", m_symbols[0].offset);

    // FirstSymAddr
    m_data.insert(m_data.end(), m_object->get_target_info()->addr_size / 8, 0);
    ElfReloc symbol_reloc(0,
                          m_object->get_target_info()->symbol_reloc,
                          m_symbols[0].symbol.as_local(), 0);
    m_object->get_target_info()->ops->add_reloc_to_buffer(m_reloc_data, &symbol_reloc);

    // FirstSymOffset
    push_back_uleb128(m_symbols[0].offset);
    push_back_uleb128(m_symbols[0].p2align);

    // Symbols
    assert(!m_include_sizes && "TODO: Handle sized symbols");
    for (unsigned i = 1; i < m_symbols.size(); ++i) {
        if (m_symbols[i].offset == m_symbols[i-1].offset)
            continue; // Ignore duplicate symbols
        Debug::printf<10>("Adding trap symbol at %u\n", m_symbols[i].offset);
        push_back_uleb128(m_symbols[i].offset-m_symbols[i-1].offset);
        push_back_uleb128(m_symbols[i].p2align);
    }
    m_data.push_back(0);
    m_data.push_back(0);

    // Relocations
    if (m_relocs.size() > 0) {
        std::sort(m_relocs.begin(),  m_relocs.end());
        write_reloc(m_relocs[0], 0, symbol_table);
        for (unsigned i = 1; i < m_relocs.size(); ++i) {
            ElfReloc &reloc = m_relocs[i];
            assert(reloc.offset != m_relocs[i-1].offset
                   && "Two relocs at the same location");
            write_reloc(reloc, m_relocs[i-1].offset, symbol_table);
        }
    }
    m_data.push_back(0);
    m_data.push_back(0);

    // Padding
    push_back_uleb128(m_padding_offset);
    push_back_uleb128(m_padding_size);
}

void TrapRecordBuilder::push_back_uleb128(Elf_Offset x) {
    if (x == 0) {
        m_data.push_back(0);
        return;
    }
    while (x >= 0x80) {
        m_data.push_back((0x80 | (x & 0x7F)));
        x >>= 7;
    }
    assert((x > 0 && x < 0x80) && "Invalid value for ULEB128");
    m_data.push_back(static_cast<uint8_t>(x));
}

void TrapRecordBuilder::push_back_sleb128(Elf_Offset x) {
    if (x == 0) {
        m_data.push_back(0);
        return;
    }
    bool more = true;
    while (more) {
        static_assert((-1 >> 1) == -1, "Compiler with support for arithmetic right shift is required");
        Elf_Offset byte = (x & 0x7F);
        x >>= 7;
        if (x ==  0 && (byte & 0x40) == 0)
            more = false;
        if (x == -1 && (byte & 0x40) != 0)
            more = false;
        if (more)
            byte |= 0x80;
        m_data.push_back(byte);
    }
}
