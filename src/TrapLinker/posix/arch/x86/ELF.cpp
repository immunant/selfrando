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
    for (auto &sym_pair : entry_symbols) {
        auto sym_index = sym_pair.first;
        m_trampoline_offsets[sym_index] = tramp_data.size()*sizeof(TrampolineInstruction);
        tramp_data.push_back(kJumpInstruction);
    }

    return ElfObject::DataBuffer(tramp_data, 1);
}

void TrampolineBuilder::add_reloc(uint32_t symbol_index, GElf_Addr trampoline_offset) {
    Target::add_reloc_to_buffer(m_trampoline_relocs,
                                trampoline_offset+1,
                                ELF32_R_INFO(symbol_index, R_386_PC32),
                                nullptr);
}

size_t TrampolineBuilder::trampoline_size() const {
    return sizeof(TrampolineInstruction);
}

void TrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
}

Elf_SectionIndex Target::create_reloc_section(ElfObject &object,
                                              const std::string &section_name,
                                              Elf_SectionIndex shndx,
                                              Elf_SectionIndex symtab_shndx) {
    // Create a new reloc section
    GElf_Shdr rel_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    rel_header.sh_type = SHT_REL;
    rel_header.sh_flags = SHF_INFO_LINK;
    rel_header.sh_entsize = sizeof(Elf32_Rel);
    rel_header.sh_link = symtab_shndx;
    rel_header.sh_info = shndx;
    rel_header.sh_addralign = sizeof(uint32_t);
    return object.add_section(".rel" + section_name, &rel_header,
                              ElfObject::DataBuffer::get_empty_buffer(),
                              ELF_T_REL);
}

void Target::add_reloc_to_buffer(Elf_RelocBuffer &buffer,
                                 GElf_Addr r_offset, GElf_Addr r_info, Elf_Offset *r_addend) {
    Elf32_Rel reloc = {r_offset, r_info};
    buffer.insert(buffer.end(),
                  reinterpret_cast<char*>(&reloc),
                  reinterpret_cast<char*>(&reloc) + sizeof(reloc));
}


void Target::add_reloc_buffer_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                                         const Elf_RelocBuffer &relocs) {
    object.add_data(reloc_shndx, const_cast<char*>(relocs.data()),
                    relocs.size(), sizeof(uint32_t), ELF_T_REL);
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
Elf_Offset Target::read_reloc(char* data, TrapReloc &reloc) {
  return *reinterpret_cast<int32_t*>(data);
}
