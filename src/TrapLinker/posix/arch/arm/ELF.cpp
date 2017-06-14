/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <Object.h>
#include <Utility.h>

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
} TrampolineInstruction;

static TrampolineInstruction kThumbJumpInstruction = {0xbffef7ff};
static TrampolineInstruction kARMJumpInstruction = {0xeafffffe};

ElfObject::DataBuffer ARMTrampolineBuilder::create_trampoline_data(
    const EntrySymbols &entry_symbols) {
    std::vector<TrampolineInstruction> tramp_data;
    for (auto &sym_pair : entry_symbols) {
        auto sym_index = sym_pair.first;
        auto &sym = sym_pair.second;
        auto sym_type = GELF_ST_TYPE(sym.st_info);
        // Determine if symbol is ARM or Thumb
        // Thumb iff STT_ARM_TFUNC or (sym.st_value & 1) != 0
        auto tramp_pos = tramp_data.size()*sizeof(TrampolineInstruction);
        if (sym_type == STT_ARM_TFUNC ||
            (sym_type == STT_FUNC && (sym.st_value & 1) != 0)) {
            // We have a Thumb symbol
            tramp_data.push_back(kThumbJumpInstruction);
            m_trampoline_offsets[sym_index] = tramp_pos | 1;
        } else {
            // We have a regular ARM symbol
            tramp_data.push_back(kARMJumpInstruction);
            m_trampoline_offsets[sym_index] = tramp_pos;
        }
    }

    return ElfObject::DataBuffer(tramp_data, 4);
}

void ARMTrampolineBuilder::add_reloc(uint32_t symbol_index, GElf_Addr trampoline_offset) {
    GElf_Addr r_info;
    if (trampoline_offset & 1)
        r_info = ELF32_R_INFO(symbol_index, R_ARM_THM_JUMP24);
    else
        r_info = ELF32_R_INFO(symbol_index, R_ARM_JUMP24);

    Target::add_reloc_to_buffer(m_trampoline_relocs, (trampoline_offset & 0xfffffffe),
                                r_info, nullptr);
}

void ARMTrampolineBuilder::target_postprocessing(unsigned tramp_section_index) {
    // Add $t and $a symbols to the trampolines
    for (auto trampoline : m_trampoline_offsets) {
        std::string symbol_name = (trampoline.second & 1) ? "$t" : "$a";
        m_symbol_table.add_local_symbol(trampoline.second & ~static_cast<GElf_Addr>(1),
                                        tramp_section_index, symbol_name,
                                        sizeof(TrampolineInstruction));
    }
}

size_t ARMTrampolineBuilder::trampoline_size() const {
    return sizeof(TrampolineInstruction);
}

std::unique_ptr<TrampolineBuilder>
Target::get_trampoline_builder(ElfObject &object,
                               ElfSymbolTable &symbol_table) {
    return std::unique_ptr<TrampolineBuilder>{new ARMTrampolineBuilder(object, symbol_table)};
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


Elf_Offset Target::read_reloc(char* data, TrapReloc &reloc) {
    uint32_t value = *reinterpret_cast<uint32_t*>(data);

    switch (reloc.type) {
    // Static 32-bit data relocs
    case R_ARM_ABS32:
    case R_ARM_REL32:
    case R_ARM_SBREL32:
    case R_ARM_AMP_VCALL9: // aka R_ARM_BREL_ADJ
    case R_ARM_TLS_DESC:
    case R_ARM_TLS_DTPMOD32:
    case R_ARM_TLS_DTPOFF32:
    case R_ARM_TLS_TPOFF32:
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
    case R_ARM_RELATIVE:
    case R_ARM_GOTOFF: // aka R_ARM_GOTOFF32
    case R_ARM_GOTPC: // aka R_ARM_BASE_PREL
    case R_ARM_BASE_ABS:
    case R_ARM_ABS32_NOI:
    case R_ARM_REL32_NOI:
    case R_ARM_TLS_GOTDESC:
    case R_ARM_PLT32_ABS:
    case R_ARM_GOT_ABS:
    case R_ARM_GOT_PREL:
    case R_ARM_GNU_VTENTRY:
    case R_ARM_GNU_VTINHERIT:
    case R_ARM_TLS_GD32:
    case R_ARM_TLS_LDM32:
    case R_ARM_TLS_LDO32:
    case R_ARM_TLS_IE32:
    case R_ARM_TLS_LE32:
    case R_ARM_TARGET1:
    case R_ARM_TARGET2:
        return *reinterpret_cast<int32_t*>(data);

     // Other data relocs
    case R_ARM_ABS16:
        return *reinterpret_cast<int16_t*>(data);
    case R_ARM_ABS8:
        return *reinterpret_cast<int8_t*>(data);
    case R_ARM_PREL31:
        return signextend<TargetInfo<32>::PtrDiff, 31>(*reinterpret_cast<uint32_t*>(data));

    // Some code relocs that need an addend
    case R_ARM_MOVW_ABS_NC:
    case R_ARM_MOVT_ABS:
        return signextend<TargetInfo<32>::PtrDiff, 16>(
            ((value >> 4) & 0xf000) |
            (value & 0xfff));

    case R_ARM_THM_MOVW_ABS_NC:
    case R_ARM_THM_MOVT_ABS:
        return signextend<TargetInfo<32>::PtrDiff, 16>(
            ((value << 12) & 0xf000) |
            ((value << 1) & 0x800) |
            ((value >> 20) & 0x700) |
            ((value >> 16) & 0xff));

    default:
        // FIXME: this should never happen, assert(false) here???
        return ElfOffset(0);
    }
}
