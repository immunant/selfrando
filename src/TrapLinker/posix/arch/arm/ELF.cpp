/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <Object.h>
#include <Utility.h>

class ARMTargetOps : public TargetOps {
public:
    ARMTargetOps() { }

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

static ARMTargetOps arm_ops_instance;
ARMTargetOps *arm_ops = &arm_ops_instance;

class ARMTrampolineBuilder : public TrampolineBuilder {
public:
    ARMTrampolineBuilder(ElfObject &object, ElfSymbolTable &symbol_table)
        : TrampolineBuilder(object, symbol_table) {
    }

    virtual ~ARMTrampolineBuilder() { }

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
} ARMTrampolineInstruction;

static ARMTrampolineInstruction kThumbJumpInstruction = {0xbffef7ff};
static ARMTrampolineInstruction kARMJumpInstruction = {0xeafffffe};

ElfObject::DataBuffer ARMTrampolineBuilder::create_trampoline_data(
    const EntrySymbols &entry_symbols) {
    std::vector<ARMTrampolineInstruction> tramp_data;
    for (auto &sym : entry_symbols) {
        auto sym_type = GELF_ST_TYPE(sym.get()->st_info);
        // Determine if symbol is ARM or Thumb
        // Thumb iff STT_ARM_TFUNC or (sym.st_value & 1) != 0
        auto tramp_pos = tramp_data.size()*sizeof(ARMTrampolineInstruction);
        if (sym_type == STT_ARM_TFUNC ||
            (sym_type == STT_FUNC && (sym.get()->st_value & 1) != 0)) {
            // We have a Thumb symbol
            tramp_data.push_back(kThumbJumpInstruction);
            m_trampoline_offsets[sym] = tramp_pos | 1;
        } else {
            // We have a regular ARM symbol
            tramp_data.push_back(kARMJumpInstruction);
            m_trampoline_offsets[sym] = tramp_pos;
        }
    }

    return ElfObject::DataBuffer(tramp_data, 4);
}

// Older versions of elf.h do not have these
#ifndef R_ARM_JUMP24
#define R_ARM_JUMP24        29
#endif
#ifndef R_ARM_THM_JUMP24
#define R_ARM_THM_JUMP24    30
#endif

void ARMTrampolineBuilder::add_reloc(ElfSymbolTable::SymbolRef symbol_index,
                                     GElf_Addr trampoline_offset) {
    if (trampoline_offset & 1) {
        ElfReloc reloc(trampoline_offset - 1, R_ARM_THM_JUMP24, symbol_index.as_local(), 0);
        arm_ops->add_reloc_to_buffer(m_trampoline_relocs, &reloc);
    } else {
        ElfReloc reloc(trampoline_offset, R_ARM_JUMP24, symbol_index.as_local(), 0);
        arm_ops->add_reloc_to_buffer(m_trampoline_relocs, &reloc);
    }
}

size_t ARMTrampolineBuilder::trampoline_size() const {
    return sizeof(ARMTrampolineInstruction);
}

void ARMTrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
    // Add $t and $a symbols to the trampolines
    for (auto trampoline : m_trampoline_offsets) {
        std::string symbol_name = (trampoline.second & 1) ? "$t" : "$a";
        m_symbol_table.add_local_symbol(trampoline.second & ~static_cast<GElf_Addr>(1),
                                        tramp_section_index, symbol_name,
                                        STT_OBJECT, sizeof(ARMTrampolineInstruction));
    }
}

std::unique_ptr<TrampolineBuilder>
ARMTargetOps::get_trampoline_builder(ElfObject &object,
                                     ElfSymbolTable &symbol_table) {
    return std::unique_ptr<TrampolineBuilder>{new ARMTrampolineBuilder(object, symbol_table)};
}

// TODO: move this to a common file shared with x86/ELF.cpp???
static std::vector<Elf32_Rel> build_rels(const Elf_RelocBuffer &relocs) {
    std::vector<Elf32_Rel> rels;
    for (auto &reloc : relocs) {
        uint32_t rel_info = ELF32_R_INFO(reloc.symbol.get_final_index(), reloc.type);
        assert(reloc.offset >= 0 && "Casting negative value to unsigned int");
        rels.push_back({ static_cast<Elf32_Addr>(reloc.offset), rel_info });
    }
    return rels;
}

Elf_SectionIndex ARMTargetOps::create_reloc_section(ElfObject &object,
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

void ARMTargetOps::add_reloc_to_buffer(Elf_RelocBuffer &buffer, ElfReloc *reloc) {
    buffer.push_back(*reloc);
}

void ARMTargetOps::add_relocs_to_section(ElfObject &object, Elf_SectionIndex reloc_shndx,
                                         const Elf_RelocBuffer &relocs) {
    std::vector<Elf32_Rel> rels = build_rels(relocs);
    object.add_data(reloc_shndx, reinterpret_cast<char*>(rels.data()),
                    rels.size() * sizeof(Elf32_Rel), sizeof(uint32_t), ELF_T_REL);
}

bool ARMTargetOps::check_rel_for_stubs(ElfObject &object, GElf_Rel *relocation, ptrdiff_t addend,
                                       uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

bool ARMTargetOps::check_rela_for_stubs(ElfObject &object, GElf_Rela *relocation, ptrdiff_t addend,
                                        uint32_t shndx, TrapRecordBuilder &builder) {
    return false;
}

Elf_Offset ARMTargetOps::read_reloc(char* data, ElfReloc &reloc) {
    uint32_t value = *reinterpret_cast<uint32_t*>(data);

    switch (reloc.type) {
    // Static 32-bit data relocs
    case   2: // R_ARM_ABS32
    case   3: // R_ARM_REL32
    case   9: // R_ARM_SBREL32
    case  12: // R_ARM_AMP_VCALL9 // aka R_ARM_BREL_ADJ
    case  13: // R_ARM_TLS_DESC
    case  17: // R_ARM_TLS_DTPMOD32
    case  18: // R_ARM_TLS_DTPOFF32
    case  19: // R_ARM_TLS_TPOFF32
    case  21: // R_ARM_GLOB_DAT
    case  22: // R_ARM_JUMP_SLOT
    case  23: // R_ARM_RELATIVE
    case  24: // R_ARM_GOTOFF // aka R_ARM_GOTOFF32
    case  25: // R_ARM_GOTPC // aka R_ARM_BASE_PREL
    case  31: // R_ARM_BASE_ABS
    case  38: // R_ARM_TARGET1
    case  41: // R_ARM_TARGET2
    case  55: // R_ARM_ABS32_NOI
    case  56: // R_ARM_REL32_NOI
    case  90: // R_ARM_TLS_GOTDESC
    case  94: // R_ARM_PLT32_ABS
    case  95: // R_ARM_GOT_ABS
    case  96: // R_ARM_GOT_PREL
    case 100: // R_ARM_GNU_VTENTRY
    case 101: // R_ARM_GNU_VTINHERIT
    case 104: // R_ARM_TLS_GD32
    case 105: // R_ARM_TLS_LDM32
    case 106: // R_ARM_TLS_LDO32
    case 107: // R_ARM_TLS_IE32
    case 108: // R_ARM_TLS_LE32
        return *reinterpret_cast<int32_t*>(data);

     // Other data relocs
    case 5:   // R_ARM_ABS16
        return *reinterpret_cast<int16_t*>(data);
    case 8:   // R_ARM_ABS8
        return *reinterpret_cast<int8_t*>(data);
    case 42:  // R_ARM_PREL31
        return signextend<Elf_Offset, 31>(*reinterpret_cast<uint32_t*>(data));

    // Some code relocs that need an addend
    case 43:  // R_ARM_MOVW_ABS_NC
    case 44:  // R_ARM_MOVT_ABS
        return signextend<Elf_Offset, 16>(
            ((value >> 4) & 0xf000) |
            (value & 0xfff));

    case 47:  // R_ARM_THM_MOVW_ABS_NC
    case 48:  // R_ARM_THM_MOVT_ABS
        return signextend<Elf_Offset, 16>(
            ((value << 12) & 0xf000) |
            ((value << 1) & 0x800) |
            ((value >> 20) & 0x700) |
            ((value >> 16) & 0xff));

    default:
        // FIXME: this should never happen, assert(false) here???
        return Elf_Offset(0);
    }
}
