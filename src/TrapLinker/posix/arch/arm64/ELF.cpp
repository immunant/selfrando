/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <Object.h>

class ARM64TargetOps : public TargetOps {
public:
    ARM64TargetOps() { }

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

static ARM64TargetOps arm64_ops_instance;
ARM64TargetOps *arm64_ops = &arm64_ops_instance;

class ARM64TrampolineBuilder : public TrampolineBuilder {
public:
    ARM64TrampolineBuilder(ElfObject &object, ElfSymbolTable &symbol_table)
        : TrampolineBuilder(object, symbol_table) {
    }

    virtual ~ARM64TrampolineBuilder() { }

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

typedef struct {
    uint32_t insn;
} ARM64TrampolineInstruction;

static ARM64TrampolineInstruction kJumpInstruction = {0x14000000};

ElfObject::DataBuffer ARM64TrampolineBuilder::create_trampoline_data(
    const EntrySymbols &entry_symbols) {
    std::vector<ARM64TrampolineInstruction> tramp_data;
    for (auto &sym : entry_symbols) {
        m_trampoline_offsets[sym] = tramp_data.size()*sizeof(ARM64TrampolineInstruction);
        tramp_data.push_back(kJumpInstruction);
    }

    return ElfObject::DataBuffer(tramp_data, 4);
}

void ARM64TrampolineBuilder::add_reloc(ElfSymbolTable::SymbolRef symbol_index,
                                       GElf_Addr trampoline_offset) {
    ElfReloc reloc(trampoline_offset, R_AARCH64_JUMP26, symbol_index.as_local(), 0);
    arm64_ops->add_reloc_to_buffer(m_trampoline_relocs, &reloc);
    assert(reloc.addend == 0 && "Invalid trampoline addend");
}

size_t ARM64TrampolineBuilder::trampoline_size() const {
    return sizeof(ARM64TrampolineInstruction);
}

void ARM64TrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
}

std::unique_ptr<TrampolineBuilder>
ARM64TargetOps::get_trampoline_builder(ElfObject &object,
                               ElfSymbolTable &symbol_table) {
    return std::unique_ptr<TrampolineBuilder>{new ARM64TrampolineBuilder(object, symbol_table)};
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

Elf_SectionIndex ARM64TargetOps::create_reloc_section(ElfObject &object,
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

void ARM64TargetOps::add_reloc_to_buffer(Elf_RelocBuffer &buffer, ElfReloc *reloc) {
    buffer.push_back(*reloc);
    reloc->addend = 0;
}


void ARM64TargetOps::add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                                           const Elf_RelocBuffer &relocs) {
    std::vector<Elf64_Rela> relas = build_relas(relocs);
    object.add_data(reloc_shndx, reinterpret_cast<char*>(relas.data()),
                    relas.size() * sizeof(Elf64_Rela), sizeof(uint64_t), ELF_T_RELA);
}

bool ARM64TargetOps::check_rel_for_stubs(ElfObject &object, GElf_Rel *relocation, ptrdiff_t addend,
                                         uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

bool ARM64TargetOps::check_rela_for_stubs(ElfObject &object, GElf_Rela *relocation, ptrdiff_t addend,
                                         uint32_t shndx, TrapRecordBuilder &builder) {
    auto r_type = GELF_R_TYPE(relocation->r_info);
    if (r_type == R_AARCH64_TSTBR14 || r_type == R_AARCH64_CONDBR19) {
        // We get a 16/21-bit PC-relative jump which might overflow,
        // so we need a stub
        auto r_sym = GELF_R_SYM(relocation->r_info);
        auto old_r_offset = relocation->r_offset;
        // TODO: we can optimize size here by de-duplicating stubs
        auto stub_offset = object.add_data(shndx, reinterpret_cast<void*>(&kJumpInstruction),
                                           sizeof(kJumpInstruction), 4);
        relocation->r_offset = stub_offset;
        relocation->r_info = ELF64_R_INFO(r_sym, R_AARCH64_JUMP26);

        auto delta = static_cast<int64_t>(stub_offset) - old_r_offset;
        uint32_t mask = (r_type == R_AARCH64_TSTBR14) ? 0x7ffe0 : 0xffffe0;
        object.add_int32_section_patch(shndx, old_r_offset, mask,
                                       static_cast<uint32_t>((delta >> 2) << 5));
        // TODO: we could add a TRaP relocation here over the original instruction,
        // so RandoLib can redirect it to the original target if the branch
        // offset fits
        // FIXME: if JUMP26 also isn't big enough to reach the target,
        // then we're gonna need a different stub
        return true;
    }
    return false;
}

// TODO: Implement any weird code relocs
Elf_Offset ARM64TargetOps::read_reloc(char* data, ElfReloc &reloc) {
  return *reinterpret_cast<Elf_Offset*>(data);
}
