/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2016 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "OS.h"
#include "TrapInfo.h"

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include <type_traits>
#include <sys/stat.h>

extern "C" {
#include "util/fnv.h"
}

#ifndef R_X86_64_GOTPCRELX
#define R_X86_64_GOTPCRELX 41
#endif

#ifndef R_X86_64_REX_GOTPCRELX
#define R_X86_64_REX_GOTPCRELX 42
#endif

namespace os {

unsigned int APIImpl::rand_seed = 0;

RANDO_SECTION void APIImpl::DebugPrintfImpl(const char *fmt, ...) {
    char tmp[256];
    ssize_t bytes_written;
    va_list args;
    va_start(args, fmt);
    vsnprintf(tmp, 255, fmt, args);
    va_end(args);
    // FIXME: find better printing output
    bytes_written = write(2, tmp, strlen(tmp));
}

RANDO_SECTION void APIImpl::SystemMessage(const char *fmt, ...) {
    // TODO: implement
}

RANDO_SECTION void API::Init() {
    ssize_t bytes_read;
    char* sseed = getenv("SELFRANDO_random_seed");
    if (sseed) {
        rand_seed = (unsigned) atol(sseed);
    } else {
        FILE* devrandom = fopen("/dev/urandom", "r");
        bytes_read = fread(&rand_seed, sizeof(rand_seed), 1, devrandom);
        rand_seed ^= (unsigned) time(NULL);
        fclose(devrandom);
    }
    // TODO: use fnv hash to mix up the seed
    DebugPrintf<1>("Rand seed:%u\n", rand_seed);
}

RANDO_SECTION void API::Finish() {
        APIImpl::rand_seed = 0;
}


RANDO_SECTION void *API::MemAlloc(size_t size, bool zeroed) {
    size = (size + sizeof(size) + kPageSize - 1) & ~kPageSize;
    auto res = reinterpret_cast<size_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    // We need to remember the size, so we know how much to munmap()
    // FIXME: MemProtect doesn't work on this
    *res = size;
    return reinterpret_cast<void*>(res + 1);
}

RANDO_SECTION void API::MemFree(void *ptr) {
    auto *size_ptr = reinterpret_cast<size_t*>(ptr);
    size_ptr--;
    munmap(size_ptr, *size_ptr);
}

// WARNING!!!: should be in the same order as the PagePermissions entries
static const int PermissionsTable[] = {
    PROT_NONE,
    PROT_READ,
    PROT_WRITE,
    PROT_READ  | PROT_WRITE,
    PROT_EXEC,
    PROT_READ  | PROT_EXEC,
    PROT_WRITE | PROT_EXEC,
    PROT_READ  | PROT_WRITE | PROT_EXEC
};

RANDO_SECTION void *API::MemMap(void *addr, size_t size, PagePermissions perms, bool commit) {
    RANDO_ASSERT(perms != PagePermissions::UNKNOWN);
    int prot_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (!commit)
        flags |= MAP_NORESERVE;
    // FIXME: we should probably manually randomize the mmap address here
    return mmap(nullptr, size, prot_perms, flags, -1, 0);
}

RANDO_SECTION void API::MemUnmap(void *addr, size_t size, bool commit) {
    munmap(addr, size);
}

RANDO_SECTION PagePermissions API::MemProtect(void *addr, size_t size, PagePermissions perms) {
    RANDO_ASSERT(perms != PagePermissions::UNKNOWN);
    int prot_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    auto paged_addr = (reinterpret_cast<uintptr_t>(addr) & ~(kPageSize - 1));
    auto paged_size = (reinterpret_cast<uintptr_t>(addr) + size) - paged_addr;
    auto res = mprotect(reinterpret_cast<void*>(paged_addr), paged_size, prot_perms);
    RANDO_ASSERT(res == 0);
    return PagePermissions::UNKNOWN;
}

RANDO_SECTION void Module::Address::Reset(const Module &mod, uintptr_t addr, AddressSpace space) {
    RANDO_ASSERT(&mod == &m_module); // We can only reset addresses to the same module
    m_address = addr;
    m_space = space;
}

RANDO_SECTION PagePermissions Module::Section::MemProtect(PagePermissions perms) const {
    // FIXME: on Linux, we might not need to do anything
    if (empty())
        return PagePermissions::NONE;
    return API::MemProtect(m_start.to_ptr(), m_size, perms);
}

RANDO_SECTION Module::Module(Handle module_info, PHdrInfoPointer phdr_info)
        : m_module_info(module_info) {
    RANDO_ASSERT(m_module_info != nullptr);
    RANDO_ASSERT(phdr_info != nullptr || m_module_info->dynamic != nullptr);
    if (phdr_info == nullptr) {
        // Iterate thru the phdr's to find the one for our dynamic_ptr
        dl_iterate_phdr([] (PHdrInfoPointer iter_info, size_t size, void *arg) {
            Module *mod = reinterpret_cast<Module*>(arg);
            for (size_t i = 0; i < iter_info->dlpi_phnum; i++) {
                auto phdr = &iter_info->dlpi_phdr[i];
                auto phdr_start = reinterpret_cast<BytePointer>(iter_info->dlpi_addr + phdr->p_vaddr);
                if (phdr->p_type == PT_DYNAMIC && mod->m_module_info->dynamic == phdr_start) {
                    // Binaries generally contain a DYNAMIC phdr
                    // so we should find one here
                    memcpy(&mod->m_phdr_info, iter_info, sizeof(*iter_info));
                    return 1;
                }
            }
            return 0;
        }, this);
    } else {
        memcpy(&m_phdr_info, phdr_info, sizeof(*phdr_info));
    }
    if (m_module_info->dynamic == nullptr) {
        // Extract m_module_info->dynamic from the phdr
        for (size_t i = 0; i < m_phdr_info.dlpi_phnum; i++) {
            auto phdr = &m_phdr_info.dlpi_phdr[i];
            if (phdr->p_type == PT_DYNAMIC) {
                m_module_info->dynamic = RVA2Address(phdr->p_vaddr).to_ptr();
                break;
            }
        }
        RANDO_ASSERT(m_module_info->dynamic != nullptr);
    }

    // Find the image base (address of the first file byte)
    // FIXME: is this 100% correct???
    m_image_base = nullptr;
    for (size_t i = 0; i < m_phdr_info.dlpi_phnum; i++) {
        auto phdr = &m_phdr_info.dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
            m_image_base = RVA2Address(phdr->p_vaddr).to_ptr();
            break;
        }
    }

    // Find the module's GOT (easy on x86, it's in DT_PLTGOT)
    typedef std::conditional<sizeof(uintptr_t) == 8, Elf64_Dyn, Elf32_Dyn>::type Elf_Dyn;
    auto dyn = reinterpret_cast<Elf_Dyn*>(m_module_info->dynamic);
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_PLTGOT) {
            m_got = reinterpret_cast<BytePointer>(dyn->d_un.d_ptr);
            break;
        }
    }
    RANDO_ASSERT(m_got != nullptr);

    size_t image_size = 0;
    for (const ElfW(Phdr)* segmp = m_phdr_info.dlpi_phdr;
        segmp < m_phdr_info.dlpi_phdr + m_phdr_info.dlpi_phnum; ++segmp) {
        if (segmp->p_type == PT_LOAD && (segmp->p_flags & PF_X)) {
            BytePointer end = RVA2Address(segmp->p_vaddr + segmp->p_memsz).to_ptr();
            if (end > m_image_base + image_size) {
                image_size = end - m_image_base;
            }
        }
    }

    // Find eh_frame_hdr
    for (const ElfW(Phdr)* segmp = m_phdr_info.dlpi_phdr;
         segmp < m_phdr_info.dlpi_phdr + m_phdr_info.dlpi_phnum; ++segmp) {

        if (segmp->p_type == PT_GNU_EH_FRAME) {
            m_eh_frame_hdr = (BytePointer) segmp->p_vaddr + m_phdr_info.dlpi_addr;
            break;
        }
    }

    API::DebugPrintf<1>("Module@%p dynamic:%p PIT:%p base:%p->%p GOT:%p eh_f_hdr:%p\n",
                        this, m_module_info->dynamic,
                        m_module_info->program_info_table,
                        m_phdr_info.dlpi_addr, m_image_base, m_got, m_eh_frame_hdr);
    LFInit(APIImpl::getRand_seed(), m_image_base - m_phdr_info.dlpi_addr, m_image_base,
           image_size, m_phdr_info.dlpi_name);
}

RANDO_SECTION void Module::MarkRandomized(Module::RandoState state) {
    // TODO: implement
    // TODO: find some unused bit inside the ELF header (somewhere) or phdr
    // FIXME: since we don't support system libraries right now,
    // we don't need to mark the randomized ones (yet)
}

RANDO_SECTION void Module::ForAllExecSections(bool self_rando, ExecSectionCallback callback, void *callback_arg) {
    // Re-map the read-only segments as RWX
    for (size_t i = 0; i < m_phdr_info.dlpi_phnum; i++) {
        auto phdr = &m_phdr_info.dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD) {
            auto seg_start = RVA2Address(phdr->p_vaddr).to_ptr();
            auto seg_perms = (phdr->p_flags & PF_X) != 0 ? PagePermissions::RWX
                                                         : PagePermissions::RW;
            // X is needed here because this code is in one of the segments
            API::MemProtect(seg_start, phdr->p_memsz, seg_perms);
        }
    }
    // FIXME: unfortunately, the loader doesn't seem to load
    // the section table into memory (it's outside the PT_LOAD segments).
    // For this reason, we need to get the executable sections from somewhere
    // else. Currently, PatchEntry takes care of this.
    for (size_t i = 0; i < TRAP_NUM_SECTIONS; i++) {
        auto &sec_info = m_module_info->program_info_table->sections[i];
        if (sec_info.start == 0 || sec_info.size == 0 ||
            sec_info.trap  == 0 || sec_info.trap_size == 0)
            continue;

        auto sec_start = sec_info.start;
        auto sec_trap_start = RVA2Address(sec_info.trap).to_ptr();
        API::DebugPrintf<1>("Module@%p sec@%p[%d] TRaP@%p[%d]\n",
                            this, sec_start, sec_info.size,
                            sec_trap_start, sec_info.trap_size);
        Section section(*this, sec_start, sec_info.size);
        TrapInfo sec_trap_info(sec_trap_start, sec_info.trap_size);
        (*callback)(*this, section, sec_trap_info, self_rando, callback_arg);
    }
    // Re-map the read-only segments with their original permissions
    for (size_t i = 0; i < m_phdr_info.dlpi_phnum; i++) {
        auto phdr = &m_phdr_info.dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD) {
            RANDO_ASSERT((phdr->p_flags & PF_R) != 0);
            auto seg_start = RVA2Address(phdr->p_vaddr).to_ptr();
            auto seg_perms = (phdr->p_flags & PF_X) != 0 ?
                             ((phdr->p_flags & PF_W) != 0 ? PagePermissions::RWX : PagePermissions::RX):
                             ((phdr->p_flags & PF_W) != 0 ? PagePermissions::RW  : PagePermissions::R );
            API::MemProtect(seg_start, phdr->p_memsz, seg_perms);
        }
    }
}

RANDO_SECTION void Module::ForAllModules(ModuleCallback callback, void *callback_arg) {
    // FIXME: we don't currently support system libraries
    // that don't provide a m_module_info->program_info_table-> and the ones
    // that do provide that table also do their own randomization
#if 0
    // We need to manually capture the callback parameters
    // to make our lambda compatible with dl_iterate_phdr
    struct ArgStruct {
        ModuleCallback callback;
        void *callback_arg;
    } arg_struct = { callback, callback_arg };
    dl_iterate_phdr([] (struct dl_phdr_info *info, size_t size, void *arg) {
        ArgStruct *arg_struct_ptr = reinterpret_cast<ArgStruct*>(arg);
        Module mod(nullptr, info);
        (*arg_struct_ptr->callback)(mod, arg_struct_ptr->callback_arg);
        return 0;
    }, &arg_struct);
#endif
}

RANDO_SECTION void Module::ForAllRelocations(Module::Relocation::Callback callback,
                                             void *callback_arg) const {
    // Fix up the original entry point and init addresses
    if (m_module_info->program_info_table->orig_dt_init != 0) {
        m_module_info->program_info_table->orig_dt_init += m_phdr_info.dlpi_addr;
        Relocation reloc(*this, address_from_ptr(&m_module_info->program_info_table->orig_dt_init),
                         Relocation::get_pointer_reloc_type());
        (*callback)(reloc, callback_arg);
    }
    if (m_module_info->program_info_table->orig_entry != 0) {
        m_module_info->program_info_table->orig_entry += m_phdr_info.dlpi_addr;
        Relocation reloc(*this, address_from_ptr(&m_module_info->program_info_table->orig_entry),
                         Relocation::get_pointer_reloc_type());
        (*callback)(reloc, callback_arg);
    }
    Fixup_eh_frame_hdr(callback, callback_arg);
}
RANDO_SECTION void Module::ForAllRelocations(const std::pair<os::BytePointer, os::BytePointer> GOT,
                                             Module::Relocation::Callback callback,
                                             void *callback_arg) const {
    ForAllRelocations(callback, callback_arg);
    os::BytePointer* got_start = reinterpret_cast<os::BytePointer*>(RVA2Address((uintptr_t) GOT.first).to_ptr());
    os::BytePointer* got_end  = reinterpret_cast<os::BytePointer*>(RVA2Address((uintptr_t) GOT.second).to_ptr());
    for (os::BytePointer* p = got_start; p < got_end; ++p) {
        Relocation reloc(*this, address_from_ptr(p), Relocation::get_pointer_reloc_type());
        (*callback)(reloc, callback_arg);
    }
}

RANDO_SECTION void Module::Fixup_eh_frame_hdr(Module::Relocation::Callback callback,
                                             void *callback_arg) const {
    uint32_t hdr = *(uint32_t*) m_eh_frame_hdr;
    RANDO_ASSERT(hdr == 0x3b031b01);
    uint32_t num_entries = *(uint32_t*) (m_eh_frame_hdr+8);

    struct eh_hdr_entry {
        int32_t function_start_pc_off;
        int32_t fde_start_off;
    };

    eh_hdr_entry* eh_hdr_entries = (eh_hdr_entry*) (m_eh_frame_hdr+12);

    for (eh_hdr_entry* entry = eh_hdr_entries; entry < eh_hdr_entries + num_entries; ++entry) {
        Relocation reloc(*this, address_from_ptr(&entry->function_start_pc_off),
                         Relocation::get_eh_frame_reloc_type());
        callback(reloc, callback_arg);
    }

    API::QuickSort(eh_hdr_entries, num_entries, sizeof(eh_hdr_entry), [] (const void* a, const void* b) {
        auto aa = (const eh_hdr_entry*) a;
        auto bb = (const eh_hdr_entry*) b;
        return aa->function_start_pc_off - bb->function_start_pc_off;
    });
}

    void Module::LFInit(unsigned int seed, BytePointer file_base, void *mem_base,
                        size_t length, const char *name) {
        if (!getenv("SELFRANDO_write_layout_file"))
            return;

        void* null = NULL;
        pid_t pid = getpid();
        char filename[32];
        snprintf(filename, sizeof(filename), "/tmp/%d.mlf", pid);

        m_layout_file = fopen(filename, "a");
        int v = 0x00000101;
        fwrite(&v, sizeof(v), 1, m_layout_file);

        API::DebugPrintf<1>("%p %p %p %p >%s< %d\n", seed, file_base, mem_base, length, name, strlen(name)+1);
        fwrite(&seed, sizeof(seed), 1, m_layout_file);
        fwrite(&file_base, sizeof(file_base), 1, m_layout_file);
        fwrite(&mem_base, sizeof(mem_base), 1, m_layout_file);
        fwrite(&length, sizeof(length), 1, m_layout_file);
        fwrite(name, 1, strlen(name)+1, m_layout_file);
//        fwrite(&null, 1, (8 - ((strlen(name)+1) % 8)) % 8, m_layout_file);
    }

    void Module::LFWriteRandomizationRecord(void *undiv_start, void *div_start, uint32_t length) const {
        if (m_layout_file) {
            fwrite(&undiv_start, sizeof(undiv_start), 1, m_layout_file);
            fwrite(&div_start, sizeof(div_start), 1, m_layout_file);
            fwrite(&length, sizeof(length), 1, m_layout_file);
        }
    }

    void Module::LFEnd() const {
        if (m_layout_file) {
            void* null = NULL;
            fwrite(&null, sizeof(null), 1, m_layout_file);
            fclose(m_layout_file);
        }
    }
}
