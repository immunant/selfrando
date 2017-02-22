/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "Object.h"
#include "../Support/Debug.h"

typedef struct {
    uint8_t opcode;
    int32_t dest;
    // We need even-sized trampolines, so they start
    // at even addresses (C++ uses odd pointers for
    // class member pointers)
    uint8_t padding[1];
} TrampolineInstruction;

static TrampolineInstruction kJumpInstruction = {0xe9, 0, {0x90}};

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
    ElfReloc reloc(trampoline_offset+1, R_X86_64_PC32, symbol_index, -4);
    Target::add_reloc_to_buffer(m_trampoline_relocs, &reloc);
    assert(reloc.addend == 0 && "Invalid trampoline addend");
}

size_t TrampolineBuilder::trampoline_size() const {
    return sizeof(TrampolineInstruction);
}

void TrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
}

static std::vector<TargetElf_Rela> build_relas(const Elf_RelocBuffer &relocs) {
    std::vector<TargetElf_Rela> relas;
    for (auto &reloc : relocs) {
        uint64_t rela_info = ELF64_R_INFO(reloc.symbol.get_final_index(), reloc.type);
        assert(reloc.offset >= 0 && "Casting negative value to unsigned int");
        relas.push_back({ (TargetElf_Addr)reloc.offset, rela_info, reloc.addend });
    }
    return relas;
}

Elf_SectionIndex Target::create_reloc_section(ElfObject &object,
                                              const std::string &section_name,
                                              Elf_SectionIndex shndx,
                                              Elf_SectionIndex symtab_shndx,
                                              const Elf_RelocBuffer &relocs) {
    // Create a new reloc section
    GElf_Shdr rel_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    rel_header.sh_type = SHT_RELA;
    rel_header.sh_flags = SHF_INFO_LINK;
    rel_header.sh_entsize = sizeof(TargetElf_Rela);
    rel_header.sh_link = symtab_shndx;
    rel_header.sh_info = shndx;
    rel_header.sh_addralign = sizeof(TargetPtr);
    std::vector<TargetElf_Rela> relas = build_relas(relocs);
    return object.add_section(".rela" + section_name, rel_header,
                              ElfObject::DataBuffer(relas, sizeof(TargetPtr)),
                              ELF_T_RELA);
}

void Target::add_reloc_to_buffer(Elf_RelocBuffer &buffer, ElfReloc *reloc) {
    buffer.push_back(*reloc);
    reloc->addend = 0;
}

void Target::add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                                   const Elf_RelocBuffer &relocs) {
    std::vector<TargetElf_Rela> relas = build_relas(relocs);
    object.add_data(reloc_shndx, reinterpret_cast<char*>(relas.data()),
                    relas.size() * sizeof(TargetElf_Rela), sizeof(TargetPtr), ELF_T_RELA);
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
TargetPtrDiff Target::read_reloc(char* data, ElfReloc &reloc) {
  return *reinterpret_cast<TargetPtrDiff*>(data);
}
