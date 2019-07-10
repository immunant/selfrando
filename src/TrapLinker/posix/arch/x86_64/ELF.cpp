/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <memory>

#include <Object.h>
#include <Debug.h>

class X8664TargetOps : public TargetOps {
public:
    X8664TargetOps() { }

    virtual Elf_SectionIndex
    create_reloc_section(ElfObject &object,
                         const std::string &section_name,
                         Elf_SectionIndex shndx,
                         Elf_SectionIndex symtab_shndx,
                         const Elf_RelocBuffer &relocs);

    virtual void
    add_reloc_to_buffer(Elf_RelocBuffer &buffer,
                        ElfReloc *reloc);

    virtual void
    add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                          const Elf_RelocBuffer &buffer);

    virtual bool
    check_rel_for_stubs(ElfObject &object, GElf_Rel *relocation, ptrdiff_t addend,
                        uint32_t shndx, TrapRecordBuilder &builder);

    virtual bool
    check_rela_for_stubs(ElfObject &object, GElf_Rela *relocation, ptrdiff_t addend,
                         uint32_t shndx, TrapRecordBuilder &builder);

    virtual Elf_Offset
    read_reloc(char* data, ElfReloc &reloc);

    virtual std::unique_ptr<TrampolineBuilder>
    get_trampoline_builder(ElfObject &object,
                           ElfSymbolTable &symbol_table);
};

static X8664TargetOps x86_64_ops_instance;
X8664TargetOps *x86_64_ops = &x86_64_ops_instance;

class X8664TrampolineBuilder : public TrampolineBuilder {
public:
    X8664TrampolineBuilder(ElfObject &object, ElfSymbolTable &symbol_table)
        : TrampolineBuilder(object, symbol_table) {
    }

    virtual ~X8664TrampolineBuilder() { }

protected:
    virtual ElfObject::DataBuffer
    create_trampoline_data(const EntrySymbols &entry_symbols);

    virtual void
    add_reloc(ElfSymbolTable::SymbolRef symbol_index, GElf_Addr trampoline_offset);

    virtual void
    target_postprocessing(unsigned tramp_section_index);

    virtual size_t
    trampoline_size() const;
};

#pragma pack(push, 1)
typedef struct {
    uint8_t opcode;
    int32_t dest;
    // We need even-sized trampolines, so they start
    // at even addresses (C++ uses odd pointers for
    // class member pointers)
    uint8_t padding[1];
} X8664TrampolineInstruction;
#pragma pack(pop)

static X8664TrampolineInstruction kJumpInstruction = {0xe9, 0, {0x90}};

ElfObject::DataBuffer X8664TrampolineBuilder::create_trampoline_data(
    const EntrySymbols &entry_symbols) {
    std::vector<X8664TrampolineInstruction> tramp_data;
    for (auto &sym : entry_symbols) {
        m_trampoline_offsets[sym] = tramp_data.size()*sizeof(X8664TrampolineInstruction);
        tramp_data.push_back(kJumpInstruction);
    }

    return ElfObject::DataBuffer(tramp_data, 1);
}

void X8664TrampolineBuilder::add_reloc(ElfSymbolTable::SymbolRef symbol_index,
                                       GElf_Addr trampoline_offset) {
    ElfReloc reloc(trampoline_offset+1, R_X86_64_PC32, symbol_index.as_local(), -4);
    x86_64_ops->add_reloc_to_buffer(m_trampoline_relocs, &reloc);
    assert(reloc.addend == 0 && "Invalid trampoline addend");
}

size_t X8664TrampolineBuilder::trampoline_size() const {
    return sizeof(X8664TrampolineInstruction);
}

void X8664TrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
}

std::unique_ptr<TrampolineBuilder>
X8664TargetOps::get_trampoline_builder(ElfObject &object,
                                       ElfSymbolTable &symbol_table) {
    return std::unique_ptr<TrampolineBuilder>{new X8664TrampolineBuilder(object, symbol_table)};
}

static std::vector<Elf64_Rela> build_relas(const Elf_RelocBuffer &relocs) {
    std::vector<Elf64_Rela> relas;
    for (auto &reloc : relocs) {
        uint64_t rela_info = ELF64_R_INFO(reloc.symbol.get_final_index(), reloc.type);
        assert(reloc.offset >= 0 && "Casting negative value to unsigned int");
        relas.push_back({ static_cast<GElf_Addr>(reloc.offset), rela_info, reloc.addend });
    }
    return relas;
}

Elf_SectionIndex X8664TargetOps::create_reloc_section(ElfObject &object,
                                                      const std::string &section_name,
                                                      Elf_SectionIndex shndx,
                                                      Elf_SectionIndex symtab_shndx,
                                                      const Elf_RelocBuffer &relocs) {
    // Create a new reloc section
    GElf_Shdr rel_header = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    rel_header.sh_type = SHT_RELA;
    rel_header.sh_flags = SHF_INFO_LINK;
    rel_header.sh_entsize = sizeof(Elf64_Rela);
    rel_header.sh_link = symtab_shndx;
    rel_header.sh_info = shndx;
    rel_header.sh_addralign = sizeof(uint64_t);
    std::vector<Elf64_Rela> relas = build_relas(relocs);
    return object.add_section(".rela" + section_name, &rel_header,
                              ElfObject::DataBuffer(relas, sizeof(uint64_t)),
                              ELF_T_RELA);
}

void X8664TargetOps::add_reloc_to_buffer(Elf_RelocBuffer &buffer, ElfReloc *reloc) {
    buffer.push_back(*reloc);
    reloc->addend = 0;
}

void X8664TargetOps::add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                                           const Elf_RelocBuffer &relocs) {
    std::vector<Elf64_Rela> relas = build_relas(relocs);
    object.add_data(reloc_shndx, reinterpret_cast<char*>(relas.data()),
                    relas.size() * sizeof(Elf64_Rela), sizeof(uint64_t), ELF_T_RELA);
}

bool X8664TargetOps::check_rel_for_stubs(ElfObject &object, GElf_Rel *relocation, ptrdiff_t addend,
                                         uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

bool X8664TargetOps::check_rela_for_stubs(ElfObject &object, GElf_Rela *relocation, ptrdiff_t addend,
                                          uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

// TODO: Implement any weird code relocs
Elf_Offset X8664TargetOps::read_reloc(char* data, ElfReloc &reloc) {
  return *reinterpret_cast<Elf_Offset*>(data);
}
