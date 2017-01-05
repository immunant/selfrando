/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <map>
#include <vector>
#include <unordered_map>
#include <tuple>
#include <type_traits>

#include <err.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>

#include <libelf.h>
#include <gelf.h>

static const char kProgramInfoTableName[] = "_TRaP_ProgramInfoTable";
static const char kEntryTrampolineName[] = "_TRaP_Linux_EntryTrampoline";
static const char kInitTrampolineName[] = "_TRaP_Linux_InitTrampoline";
static const char *kExecSections[][2] = {
    { ".text", ".txtrp" }, // FIXME: ".trap.text" would be nicer
    { ".plt", ".trap.plt" }
};

#if RANDOLIB_ARCH_SIZE == 64
typedef uint64_t ArchPointer;
typedef uint64_t ArchSize;
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Dyn  Elf_Dyn;
typedef Elf64_Sym  Elf_Sym;
#elif RANDOLIB_ARCH_SIZE == 32
typedef uint32_t ArchPointer;
typedef uint32_t ArchSize;
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Dyn  Elf_Dyn;
typedef Elf32_Sym  Elf_Sym;
#else
#error Unsupported architecture size!
#endif

// FIXME: move this to a header shared with RandoLib
enum {
    TRAP_SECTION_TEXT = 0,
    TRAP_SECTION_PLT,
    // Total number of sections
    TRAP_NUM_SECTIONS
};

// FIXME: move these to a common header
struct TrapSectionInfoTable {
    ArchPointer start, trap;
    ArchSize size, trap_size;
};

// ELF-specific information that PatchEntry fills in
struct TrapProgramInfoTable {
    ArchPointer orig_dt_init;
    ArchPointer orig_entry;

    // Location of export trampoline table
    ArchPointer xptramp_start;
    ArchSize xptramp_size;

    // Location of .text section
    // FIXME: for now, assume that there is only a fixed
    // number of sections and they contain all the code
    // Custom linker scripts may break this
    // We still put in a num_sections field, for future use
    // Also, we use num_sections to mark whether
    // we've added the sections to the table or not
    ArchSize num_sections;
    TrapSectionInfoTable sections[TRAP_NUM_SECTIONS];
};

typedef std::pair<Elf_Scn*, GElf_Shdr> ElfSectionInfo;
typedef std::tuple<ElfSectionInfo, Elf_Data*, ArchSize> ElfSectionDataInfo;

struct ElfDynamicInfo {
  ElfSectionInfo info;
  Elf_Data* data;
  size_t index;
  GElf_Dyn dyn_section;
  ElfDynamicInfo(ElfSectionInfo info, Elf_Data* data, size_t index, GElf_Dyn dyn_section) :
      info(info), data(data), index(index), dyn_section(dyn_section) {};
  ElfDynamicInfo() : data(nullptr), index(-1) {};
};

// FIXME: we have to use ElfN_Sym here, because we write it to disk directly
typedef std::tuple<ArchPointer, ArchSize, ArchPointer> ExportTrampoline;
typedef std::vector<ExportTrampoline> ExportTrampolineVector;
typedef std::pair<ArchPointer, Elf_Sym> DynamicSymbolInfo;
typedef std::unordered_multimap<ArchPointer, DynamicSymbolInfo> DynamicSymbolMap;

static ElfSectionInfo FindSectionByType(Elf *e, uint32_t type) {
    Elf_Scn *scn = nullptr;
    GElf_Shdr shdr;
    for (;;) {
        scn = elf_nextscn(e, scn);
        if (scn == nullptr)
            errx(EX_SOFTWARE, "Binary does not contain section type:%u", type);
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == type)
            return std::make_pair(scn, shdr);
    }
    return std::make_pair(nullptr, shdr);
}

static ElfSectionInfo FindSectionByName(Elf *e, const char *name) {
    size_t shstrndx;
    elf_getshdrstrndx(e, &shstrndx);

    Elf_Scn *scn = nullptr;
    GElf_Shdr shdr;
    for (;;) {
        scn = elf_nextscn(e, scn);
        if (scn == nullptr)
            return std::make_pair(nullptr, shdr);
        gelf_getshdr(scn, &shdr);
        auto sec_name = elf_strptr(e, shstrndx, shdr.sh_name);
        if (strcmp(sec_name, name) == 0)
            return std::make_pair(scn, shdr);
    }
}

static ElfSectionDataInfo FindSectionDataByAddr(Elf *e, Elf_Addr addr) {
    Elf_Scn *scn = nullptr;
    Elf_Data *data = nullptr;
    GElf_Shdr shdr;
    for (;;) {
        scn = elf_nextscn(e, scn);
        if (scn == nullptr)
            errx(EX_SOFTWARE, "Binary does not contain section with address:%lu", addr);
        gelf_getshdr(scn, &shdr);
        for (data = nullptr;;) {
            data = elf_getdata(scn, data);
            if (data == nullptr)
                break;
            auto data_start = shdr.sh_addr + data->d_off;
            auto data_end   = data_start + data->d_size;
            if (addr >= data_start && addr < data_end)
                return std::make_tuple(std::make_pair(scn, shdr),
                                       data, addr - data_start);
        }
    }
    return std::make_tuple(std::make_pair(nullptr, shdr), nullptr, 0);

}

static ElfDynamicInfo* FindDynamicInit(Elf *e) {
    auto dyn_scn = FindSectionByType(e, SHT_DYNAMIC);
    Elf_Data *dyn_data = nullptr;
    GElf_Dyn dyn;
    for (;;) {
        dyn_data = elf_getdata(dyn_scn.first, dyn_data);
        if (dyn_data == nullptr)
            break;
        for (size_t i = 0;; i++) {
            gelf_getdyn(dyn_data, i, &dyn);
            if (dyn.d_tag == DT_INIT)
                return new ElfDynamicInfo(dyn_scn, dyn_data, i, dyn);
            if (dyn.d_tag == DT_NULL)
                break;
        }
    }
    return nullptr;
}

static GElf_Sym FindSymbol(Elf *e, const char *name) {
    auto sym_scn = FindSectionByType(e, SHT_SYMTAB);
    auto sym_data = elf_getdata(sym_scn.first, nullptr);
    auto num_syms = sym_scn.second.sh_size / sym_scn.second.sh_entsize;
    for (size_t i = 0; i < num_syms; i++) {
        GElf_Sym sym;
        gelf_getsym(sym_data, i, &sym);
        auto sym_name = elf_strptr(e, sym_scn.second.sh_link, sym.st_name);
        if (strcmp(sym_name, name) == 0)
            return sym;
    }
    errx(EX_SOFTWARE, "Binary does not contain symbol:%s", name);
    return GElf_Sym();
}

static DynamicSymbolMap FindDynamicSymbols(Elf *e) {
    DynamicSymbolMap res;
    auto sym_scn = FindSectionByType(e, SHT_DYNSYM);
    auto sym_data = elf_getdata(sym_scn.first, nullptr);
    auto num_syms = sym_scn.second.sh_size / sym_scn.second.sh_entsize;
    for (size_t i = 0; i < num_syms; i++) {
        Elf_Sym &sym = reinterpret_cast<Elf_Sym*>(sym_data->d_buf)[i];
        auto sym_type = ELF32_ST_TYPE(sym.st_info);
        // FIXME: other invalid values for st_shndx???
        if (sym_type == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
            auto sym_ofs = sym_scn.second.sh_offset +
                           sym_data->d_off +
                           i * sym_scn.second.sh_entsize;
            auto sym_map_value = std::make_pair(sym_ofs, sym);
            res.insert(std::make_pair(sym.st_value, sym_map_value));
        }
    }
    return res;
}

static ExportTrampolineVector FindExportTrampolines(Elf *e,
                                                    const ElfSectionInfo &xptramp_info) {
    auto sym_scn = FindSectionByType(e, SHT_DYNSYM);
    auto sym_data = elf_getdata(sym_scn.first, nullptr);
    auto syms = reinterpret_cast<Elf_Sym*>(sym_data->d_buf);

    ExportTrampolineVector res;
    // FIXME: this assumes that the whole section
    // is inside a single Elf_Data object
    auto xptramp_data = elf_getdata(xptramp_info.first, nullptr);
    auto xptramp_start = reinterpret_cast<uint8_t*>(xptramp_data->d_buf);
    auto xptramp_end = xptramp_start + xptramp_data->d_size;
    for (auto ptr = xptramp_start; ptr < xptramp_end;) {
        auto addr = xptramp_info.second.sh_addr   + xptramp_data->d_off + (ptr - xptramp_start);
        auto  ofs = xptramp_info.second.sh_offset + xptramp_data->d_off + (ptr - xptramp_start);
        auto arg = *reinterpret_cast<uint32_t*>(ptr + 1);
        switch(ptr[0]) {
        case 0x01:
            res.emplace_back(addr, ofs, syms[arg].st_value);
            break;
        case 0xE9:
            break;
        default:
            errx(EX_SOFTWARE, ".xptramp section has invalid byte: %hhd\n", ptr[0]);
        }
        ptr += 5;
    }
    return res;
}

static void WriteExportSymbols(int fd, const ElfSectionInfo &xptramp_info,
                               const ExportTrampolineVector &xptramp_vec,
                               size_t xptramp_shndx,
                               DynamicSymbolMap &dyn_sym_map) {
    if (xptramp_vec.empty())
        return;
    ssize_t bytes_written;
    char jump_opcode = 0xE9;
    // For each trampoline, find the symbol
    for (auto &xptramp : xptramp_vec) {
        auto &xptramp_addr   = std::get<0>(xptramp);
        auto &xptramp_ofs    = std::get<1>(xptramp);
        auto &xptramp_target = std::get<2>(xptramp);
        uint32_t jump_delta = xptramp_target - (xptramp_addr + 5);
        lseek(fd, xptramp_ofs, SEEK_SET);
        bytes_written = write(fd, &jump_opcode, sizeof(jump_opcode));
        bytes_written = write(fd, &jump_delta, sizeof(jump_delta));

        // Update the symbol
        auto syms_range = dyn_sym_map.equal_range(xptramp_target);
        for (auto it = syms_range.first; it != syms_range.second; ++it) {
            auto &xptramp_dyn_sym = it->second.second;
            if (xptramp_dyn_sym.st_shndx == xptramp_shndx)
                continue;

            assert(xptramp_target == xptramp_dyn_sym.st_value);
            xptramp_dyn_sym.st_value = xptramp_addr;
            xptramp_dyn_sym.st_shndx = xptramp_shndx;
        }
    }
    for (auto &dyn_sym : dyn_sym_map) {
        auto &sym_addr = dyn_sym.first;
        auto &sym_ofs = dyn_sym.second.first;
        auto &sym = dyn_sym.second.second;
        lseek(fd, sym_ofs, SEEK_SET);
        bytes_written = write(fd, &sym, sizeof(sym));
    }
}

int main(int argc, const char *argv[]) {
    ssize_t bytes_written; // only used to silence compiler warnings 
    if (argc < 2)
        errx(EX_USAGE, "Usage: PatchEntry <binary>");

    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(EX_SOFTWARE, "Invalid ELF version: %s", elf_errmsg(-1));

    int fd = open(argv[1], O_RDWR);
    if (fd == -1)
        err(EX_NOINPUT, "open() failed");

    Elf *e;
    e = elf_begin(fd, ELF_C_RDWR, NULL);
    if (e == nullptr)
        errx(EX_SOFTWARE, "Failed to read from ELF file: %s", elf_errmsg(-1));

    if (elf_kind(e) != ELF_K_ELF)
        errx(EX_SOFTWARE, "File is not an ELF object");

    // Read the ELF header to find the entry point
    // FIXME: check the class/architecture, make sure it's the same as ours
    GElf_Ehdr elf_hdr;
    if (gelf_getehdr(e, &elf_hdr) == NULL)
        errx(EX_SOFTWARE, "Failed to read ELF header: %s", elf_errmsg(-1));

    auto dt_init = FindDynamicInit(e);
    auto dt_init_ofs = 0;
    if (dt_init) {
        dt_init_ofs = dt_init->info.second.sh_offset +
                      dt_init->data->d_off +
                      dt_init->index * sizeof(Elf_Dyn) +
                      offsetof(Elf_Dyn, d_un);
    }

    auto pit_sym = FindSymbol(e, kProgramInfoTableName);
    auto pit_info = FindSectionDataByAddr(e, pit_sym.st_value);
    auto pit_ofs = std::get<0>(pit_info).second.sh_offset + // Section file offset
                   std::get<1>(pit_info)->d_off +           // Elf_Data offset
                   std::get<2>(pit_info);                   // Offset relative to Elf_Data
#if 1
    if (dt_init)
        printf("Old ELF entry:%p DT_INIT:%p@%x PIT:%p@%lx\n",
               (void*) elf_hdr.e_entry,
               (void*) dt_init->dyn_section.d_un.d_ptr,
               dt_init_ofs,
               (void*) pit_sym.st_value,
               pit_ofs);
    else
        printf("Old ELF entry:%p DT_INIT:NULL PIT:%p@%lx\n",
               (void*) elf_hdr.e_entry,
               (void*) pit_sym.st_value,
               pit_ofs);
#endif

    // Replace the ProgramInfoTable values
    auto pit_data = std::get<1>(pit_info);
    auto orig_pit = reinterpret_cast<TrapProgramInfoTable*>(
        reinterpret_cast<uint8_t*>(pit_data->d_buf) + std::get<2>(pit_info));
    TrapProgramInfoTable pit = *orig_pit; // Need to copy it here, since elf_end releases it
    if (pit.num_sections != 0)
       errx(EX_USAGE, "Binary already contains full ProgramInfoTable structure");
    if (dt_init)
        pit.orig_dt_init = dt_init->dyn_section.d_un.d_ptr;
    else
        pit.orig_dt_init = 0;
    pit.orig_entry = elf_hdr.e_entry;

    // Find executable sections in the binary (.text/.plt/others)
    // then copy them over to the PIT
    pit.num_sections = TRAP_NUM_SECTIONS;
    for (size_t i = 0; i < TRAP_NUM_SECTIONS; i++) {
        auto sec_info = FindSectionByName(e, kExecSections[i][0]);
        if (sec_info.first != nullptr) {
            pit.sections[i].start = sec_info.second.sh_addr;
            pit.sections[i].size = sec_info.second.sh_size;
        }
        auto trap_sec_info = FindSectionByName(e, kExecSections[i][1]);
        if (trap_sec_info.first != nullptr) {
            pit.sections[i].trap = trap_sec_info.second.sh_addr;
            pit.sections[i].trap_size = trap_sec_info.second.sh_size;
        }
    }

    // Set the new entry point addresses
    auto entry_trampoline_sym = FindSymbol(e, kEntryTrampolineName);
    auto init_trampoline_sym  = FindSymbol(e, kInitTrampolineName);
    elf_hdr.e_entry = entry_trampoline_sym.st_value;
    auto new_dt_init = static_cast<ArchPointer>(init_trampoline_sym.st_value);

    // Find export trampolines
    auto xptramp_info = FindSectionByName(e, ".xptramp");
    DynamicSymbolMap dyn_sym_map;
    ExportTrampolineVector xptramp_vec;
    size_t xptramp_shndx = 0;
    if (xptramp_info.first != nullptr) {
        pit.xptramp_start = xptramp_info.second.sh_addr;
        pit.xptramp_size  = xptramp_info.second.sh_size;
        dyn_sym_map = FindDynamicSymbols(e);
        xptramp_vec = FindExportTrampolines(e, xptramp_info);
        xptramp_shndx = elf_ndxscn(xptramp_info.first);
    }

    // Update the ELF header, then write it out
    // There's some pretty ugly behavior from libelf here:
    // if we let it handle the layout, it mis-aligns the data sections
    // It also doesn't seem to update the contents correctly,
    // so we do that manually
    elf_flagelf(e, ELF_C_SET, ELF_F_LAYOUT);
    gelf_update_ehdr(e, &elf_hdr);
    if (elf_update(e, ELF_C_WRITE) <= 0)
        errx(EX_SOFTWARE, "Couldn't update ELF file: %s", elf_errmsg(-1));
    elf_end(e);

    // FIXME: libelf shenanigans force us to
    // write data out to the file manually
    // 1) DT_INIT inside .dynamic
    if (dt_init) {
        printf("writing new DT_INIT: 0x%lu\n", new_dt_init);
        lseek(fd, dt_init_ofs, SEEK_SET);
        bytes_written = write(fd, &new_dt_init, sizeof(new_dt_init));
    }
    // 2) The ProgramInfoTable
    lseek(fd, pit_ofs, SEEK_SET);
    bytes_written = write(fd, &pit, sizeof(pit));
    // 3) Exported symbols
    WriteExportSymbols(fd, xptramp_info, xptramp_vec, xptramp_shndx, dyn_sym_map);
    close(fd);
    return 0;
}
