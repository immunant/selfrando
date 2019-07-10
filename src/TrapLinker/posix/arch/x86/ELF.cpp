/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <Object.h>
#include <Debug.h>

class X86TargetOps : public TargetOps {
public:
    X86TargetOps() { }

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

static X86TargetOps x86_ops_instance;
X86TargetOps *x86_ops = &x86_ops_instance;

class X86TrampolineBuilder : public TrampolineBuilder {
public:
    X86TrampolineBuilder(ElfObject &object, ElfSymbolTable &symbol_table)
        : TrampolineBuilder(object, symbol_table) {
    }

    virtual ~X86TrampolineBuilder() { }

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
} X86TrampolineInstruction;
#pragma pack(pop)

static X86TrampolineInstruction kJumpInstruction = {0xe9, -4, {0x90}};

ElfObject::DataBuffer X86TrampolineBuilder::create_trampoline_data(
    const EntrySymbols &entry_symbols) {
    std::vector<X86TrampolineInstruction> tramp_data;
    for (auto &sym : entry_symbols) {
        m_trampoline_offsets[sym] = tramp_data.size()*sizeof(X86TrampolineInstruction);
        tramp_data.push_back(kJumpInstruction);
    }

    return ElfObject::DataBuffer(tramp_data, 1);
}

void X86TrampolineBuilder::add_reloc(ElfSymbolTable::SymbolRef symbol_index,
                                     GElf_Addr trampoline_offset) {
    ElfReloc reloc(trampoline_offset+1, R_386_PC32, symbol_index.as_local(), -4);
    x86_ops->add_reloc_to_buffer(m_trampoline_relocs, &reloc);
}

size_t X86TrampolineBuilder::trampoline_size() const {
    return sizeof(X86TrampolineInstruction);
}

void X86TrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
}

std::unique_ptr<TrampolineBuilder>
X86TargetOps::get_trampoline_builder(ElfObject &object,
                                     ElfSymbolTable &symbol_table) {
    return std::unique_ptr<TrampolineBuilder>{new X86TrampolineBuilder(object, symbol_table)};
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

Elf_SectionIndex X86TargetOps::create_reloc_section(ElfObject &object,
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

void X86TargetOps::add_reloc_to_buffer(Elf_RelocBuffer &buffer, ElfReloc *reloc) {
    buffer.push_back(*reloc);
}

void X86TargetOps::add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                                         const Elf_RelocBuffer &relocs) {
    std::vector<Elf32_Rel> rels = build_rels(relocs);
    object.add_data(reloc_shndx, reinterpret_cast<char*>(rels.data()),
                    rels.size() * sizeof(Elf32_Rel), sizeof(uint32_t), ELF_T_REL);
}

bool X86TargetOps::check_rel_for_stubs(ElfObject &object, GElf_Rel *relocation, ptrdiff_t addend,
                                       uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

bool X86TargetOps::check_rela_for_stubs(ElfObject &object, GElf_Rela *relocation, ptrdiff_t addend,
                                        uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

// TODO: Implement any weird code relocs
Elf_Offset X86TargetOps::read_reloc(char* data, ElfReloc &reloc) {
  return *reinterpret_cast<int32_t*>(data);
}
