/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <Object.h>
#include <Debug.h>

typedef struct {
    uint8_t opcode;
    int32_t dest;
    // We need even-sized trampolines, so they start
    // at even addresses (C++ uses odd pointers for
    // class member pointers)
    uint8_t padding[1];
} TrampolineInstruction;

static TrampolineInstruction kJumpInstruction = {0xe9, -4, {0x90}};

ElfObject::DataBuffer TrampolineBuilder::create_trampoline_data(
    const Target::EntrySymbols &entry_symbols) {
    std::vector<TrampolineInstruction> tramp_data;
    for (auto &sym : entry_symbols) {
        m_trampoline_offsets[sym] = tramp_data.size()*sizeof(TrampolineInstruction);
        tramp_data.push_back(kJumpInstruction);
    }

    return ElfObject::DataBuffer(tramp_data, 1);
}

void TrampolineBuilder::add_reloc(ElfSymbolTable::SymbolRef symbol_index,
                                  GElf_Addr trampoline_offset) {
    ElfReloc reloc(trampoline_offset+1, R_386_PC32, symbol_index, -4);
    Target::add_reloc_to_buffer(m_trampoline_relocs, &reloc);
}

size_t TrampolineBuilder::trampoline_size() const {
    return sizeof(TrampolineInstruction);
}

void TrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
}

static std::vector<Elf32_Rel> build_rels(const Elf_RelocBuffer &relocs) {
    std::vector<Elf32_Rel> rels;
    for (auto &reloc : relocs) {
        uint32_t rel_info = ELF32_R_INFO(reloc.symbol.get_final_index(), reloc.type);
        assert(reloc.offset >= 0 && "Casting negative value to unsigned int");
        rels.push_back({ static_cast<Elf32_Addr>(reloc.offset), rel_info });
    }
    return rels;
}

Elf_SectionIndex Target::create_reloc_section(ElfObject &object,
                                              const std::string &section_name,
                                              Elf_SectionIndex shndx,
                                              Elf_SectionIndex symtab_shndx,
                                              const Elf_RelocBuffer &relocs) {
    // Create a new reloc section
    GElf_Shdr rel_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    rel_header.sh_type = SHT_REL;
    rel_header.sh_flags = SHF_INFO_LINK;
    rel_header.sh_entsize = sizeof(Elf32_Rel);
    rel_header.sh_link = symtab_shndx;
    rel_header.sh_info = shndx;
    rel_header.sh_addralign = sizeof(uint32_t);
    std::vector<Elf32_Rel> rels = build_rels(relocs);
    return object.add_section(".rel" + section_name, &rel_header,
                              ElfObject::DataBuffer(rels, sizeof(uint32_t)),
                              ELF_T_REL);
}

void Target::add_reloc_to_buffer(Elf_RelocBuffer &buffer, ElfReloc *reloc) {
    buffer.push_back(*reloc);
}

void Target::add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                                   const Elf_RelocBuffer &relocs) {
    std::vector<Elf32_Rel> rels = build_rels(relocs);
    object.add_data(reloc_shndx, reinterpret_cast<char*>(rels.data()),
                    rels.size() * sizeof(Elf32_Rel), sizeof(uint32_t), ELF_T_REL);
}

template<typename RelType>
bool Target::check_rel_for_stubs(ElfObject &object, RelType *relocation, ptrdiff_t addend,
                                 uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

template
bool Target::check_rel_for_stubs<GElf_Rel>(ElfObject &object, GElf_Rel *relocation, ptrdiff_t addend,
                                           uint32_t shndx, TrapRecordBuilder &builder);

template
bool Target::check_rel_for_stubs<GElf_Rela>(ElfObject &object, GElf_Rela *relocation, ptrdiff_t addend,
                                            uint32_t shndx, TrapRecordBuilder &builder);

// TODO: Implement any weird code relocs
Elf_Offset Target::read_reloc(char* data, ElfReloc &reloc) {
  return *reinterpret_cast<int32_t*>(data);
}
