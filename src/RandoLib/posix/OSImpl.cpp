/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>
#include <RandoLib.h>
#include <TrapInfo.h>

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

#include <type_traits>

#if RANDOLIB_IS_ANDROID
#include <jni.h>
#include <android/log.h>
#endif

extern "C" {
#include "util/fnv.h"

int _TRaP_vsnprintf(char*, size_t, const char*, va_list);

void *_TRaP_libc_mmap(void*, size_t, int, int, int, off_t);
void *_TRaP_libc_mremap(void*, size_t, size_t, int, ...);
int _TRaP_libc_munmap(void*, size_t);
int _TRaP_libc_mprotect(const void*, size_t, int);
int _TRaP_libc_unlinkat(int, const char*, int);

void _TRaP_rand_close_fd(void);
}

namespace os {

uint32_t APIImpl::rand_seed[RANDOLIB_SEED_WORDS] = {0};

#if RANDOLIB_LOG_TO_FILE || RANDOLIB_LOG_TO_DEFAULT
int APIImpl::log_fd = -1;
#endif

#if RANDOLIB_DEBUG_LEVEL_IS_ENV
#ifdef RANDOLIB_DEBUG_LEVEL
int API::debug_level = RANDOLIB_DEBUG_LEVEL;
#else
int API::debug_level = 0;
#endif
#endif

RANDO_SECTION void APIImpl::debug_printf_impl(const char *fmt, ...) {
#if (RANDOLIB_LOG_TO_DEFAULT || RANDOLIB_LOG_TO_CONSOLE || \
     RANDOLIB_LOG_TO_FILE)
    char tmp[256];
    va_list args;
    va_start(args, fmt);
    int len = _TRaP_vsnprintf(tmp, 255, fmt, args);
    va_end(args);
    // FIXME: find better printing output
#if RANDOLIB_LOG_TO_CONSOLE
    _TRaP_libc_write(2, tmp, len);
#elif RANDOLIB_LOG_TO_FILE || RANDOLIB_LOG_TO_DEFAULT
    if (log_fd > 0)
        _TRaP_libc_write(log_fd, tmp, len);
#endif
#elif RANDOLIB_LOG_TO_SYSTEM
    va_list args;
    va_start(args, fmt);
    __android_log_vprint(ANDROID_LOG_DEBUG, "selfrando", fmt, args);
    va_end(args);
#elif RANDOLIB_LOG_TO_NONE
    // Nothing to do here
#else
#error Unknown logging option!
#endif
}

RANDO_SECTION void APIImpl::SystemMessage(const char *fmt, ...) {
    // TODO: implement
}

RANDO_SECTION void API::init() {
#if RANDOLIB_DEBUG_LEVEL_IS_ENV
    const char *debug_level_var = getenv("SELFRANDO_debug_level");
    if (debug_level_var != nullptr)
        debug_level = _TRaP_libc_strtol(debug_level_var, nullptr, 0);
#endif

#if RANDOLIB_LOG_TO_FILE || RANDOLIB_LOG_TO_DEFAULT
    int log_flags = O_CREAT | O_WRONLY | O_SYNC;
#if RANDOLIB_LOG_APPEND
    log_flags |= O_APPEND;
#endif

#define STRINGIFY(x)    #x
#define STRINGIFY_MACRO(x)    STRINGIFY(x)
    log_fd = _TRaP_libc_open(STRINGIFY_MACRO(RANDOLIB_LOG_FILENAME), log_flags, 0660);
#undef STRINGIFY
#undef STRINGIFY_MACRO
#endif

#if RANDOLIB_RNG_IS_RAND_R
#ifdef RANDOLIB_DEBUG_SEED
    rand_seed[0] = RANDOLIB_DEBUG_SEED;
#else // RANDOLIB_DEBUG_SEED
    const char *seed_var = getenv("SELFRANDO_random_seed");
    if (seed_var != nullptr) {
        rand_seed[0] = _TRaP_libc_strtol(seed_var, nullptr, 0);
    } else {
        rand_seed[0] = API::time();
    }
#endif // RANDOLIB_DEBUG_SEED
    // TODO: use fnv hash to mix up the seed
    debug_printf<1>("Rand seed:%u\n", rand_seed[0]);
#elif RANDOLIB_RNG_IS_URANDOM
    debug_printf<1>("Using /dev/urandom as RNG\n");
#else
#error Unknown RNG setting
#endif
}

RANDO_SECTION void API::finish() {
    debug_printf<1>("Finished randomizing\n");
#if RANDOLIB_LOG_TO_FILE || RANDOLIB_LOG_TO_DEFAULT
    if (log_fd != -1)
        _TRaP_libc____close(log_fd);
#endif
#if RANDOLIB_RNG_IS_URANDOM
    _TRaP_rand_close_fd();
#endif

    for (size_t i = 0; i < RANDOLIB_SEED_WORDS; i++)
        rand_seed[i] = 0;
}


RANDO_SECTION void *API::mem_alloc(size_t size, bool zeroed) {
    size = (size + sizeof(size) + kPageSize - 1) & ~kPageSize;
    auto res = reinterpret_cast<size_t*>(_TRaP_libc_mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    // We need to remember the size, so we know how much to munmap()
    // FIXME: mprotect doesn't work on this
    *res = size;
    return reinterpret_cast<void*>(res + 1);
}

RANDO_SECTION void *API::mem_realloc(void *old_ptr, size_t new_size, bool zeroed) {
    if (old_ptr == nullptr)
        return mem_alloc(new_size, zeroed);

    auto *old_size_ptr = reinterpret_cast<size_t*>(old_ptr);
    old_size_ptr--;

    auto old_size = *old_size_ptr;
    new_size = (new_size + sizeof(new_size) + kPageSize - 1) & ~kPageSize;
    if (new_size == old_size)
        return old_ptr;

    auto res = reinterpret_cast<size_t*>(_TRaP_libc_mremap(old_size_ptr, old_size,
                                                           new_size, MREMAP_MAYMOVE));
    *res = new_size;
    return reinterpret_cast<void*>(res + 1);
}

RANDO_SECTION void API::mem_free(void *ptr) {
    auto *size_ptr = reinterpret_cast<size_t*>(ptr);
    size_ptr--;
    _TRaP_libc_munmap(size_ptr, *size_ptr);
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

RANDO_SECTION void *API::mmap(void *addr, size_t size, PagePermissions perms, bool commit) {
    RANDO_ASSERT(perms != PagePermissions::UNKNOWN);
    int prot_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (!commit)
        flags |= MAP_NORESERVE;
    if (addr != nullptr)
        flags |= MAP_FIXED;
    // FIXME: we should probably manually randomize the mmap address here
    auto new_addr =_TRaP_libc_mmap(addr, size, prot_perms, flags, -1, 0);
    return new_addr == MAP_FAILED ? nullptr : new_addr;
}

RANDO_SECTION void API::munmap(void *addr, size_t size, bool commit) {
    _TRaP_libc_munmap(addr, size);
}

RANDO_SECTION PagePermissions API::mprotect(void *addr, size_t size, PagePermissions perms) {
    RANDO_ASSERT(perms != PagePermissions::UNKNOWN);
    int prot_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    auto paged_addr = (reinterpret_cast<uintptr_t>(addr) & ~(kPageSize - 1));
    auto paged_size = (reinterpret_cast<uintptr_t>(addr) + size) - paged_addr;
    _TRaP_libc_mprotect(reinterpret_cast<void*>(paged_addr), paged_size, prot_perms);
    return PagePermissions::UNKNOWN;
}

RANDO_SECTION File API::open_file(const char *name, bool write, bool create) {
    int flags = O_CLOEXEC;
    if (write) {
        flags |= O_RDWR | O_APPEND;
    } else {
        flags |= O_RDONLY;
    }
    if (create)
        flags |= O_CREAT;
    int fd = _TRaP_libc_open(name, flags, 0660);
    return fd < 0 ? kInvalidFile : fd;
}

RANDO_SECTION ssize_t API::write_file(File file, const void *buf, size_t len) {
    RANDO_ASSERT(file != kInvalidFile);
    return _TRaP_libc_write(file, buf, len);
}

RANDO_SECTION void API::close_file(File file) {
    RANDO_ASSERT(file != kInvalidFile);
    _TRaP_libc____close(file);
}

#if RANDOLIB_WRITE_LAYOUTS > 0
template<size_t len>
static inline int build_pid_filename(char (&filename)[len], const char *fmt, ...) {
    int res;
    va_list args;
    va_start(args, fmt);
    res = _TRaP_vsnprintf(filename, len - 1, fmt, args);
    va_end(args);
    return res;
}

RANDO_SECTION File API::open_layout_file(bool write) {
    char filename[32];
    build_pid_filename(filename, "/tmp/%d.mlf", API::getpid());
    return API::open_file(filename, write, true);
}

#if RANDOLIB_DELETE_LAYOUTS > 0
RANDO_PUBLIC_FUNCTION(Linux_delete_layout_file, void, void) {
    // TODO: don't delete if disabled via environment variable
    char filename[32];
    build_pid_filename(filename, "/tmp/%d.mlf", API::getpid());
    _TRaP_libc_unlinkat(AT_FDCWD, filename, 0);
}
#endif // RANDOLIB_DELETE_LAYOUTS
#endif // RANDOLIB_WRITE_LAYOUTS

RANDO_SECTION PagePermissions Module::Section::change_permissions(PagePermissions perms) const {
    // FIXME: on Linux, we might not need to do anything
    if (empty())
        return PagePermissions::NONE;
    return API::mprotect(m_start.to_ptr(), m_size, perms);
}

RANDO_SECTION Module::Module(Handle module_info, PHdrInfoPointer phdr_info)
        : ModuleBase(), m_module_info(module_info) {
    RANDO_ASSERT(m_module_info != nullptr);
    RANDO_ASSERT(phdr_info != nullptr || m_module_info->dynamic != nullptr);
    os::API::debug_printf<5>("Program info table:\n");
    os::API::debug_printf<5>("  orig_dt_init: %p\n", m_module_info->program_info_table->orig_dt_init);
    os::API::debug_printf<5>("  orig_entry: %p\n", m_module_info->program_info_table->orig_entry);
    os::API::debug_printf<5>("  xptramp: %p (%u)\n", m_module_info->program_info_table->xptramp_start,
                             m_module_info->program_info_table->xptramp_size);
    os::API::debug_printf<5>("  text: %p (%u)\n", m_module_info->program_info_table->sections[0].start,
                             m_module_info->program_info_table->sections[0].size);
    os::API::debug_printf<5>("  trap: %p (%u)\n", m_module_info->program_info_table->sections[0].trap,
                             m_module_info->program_info_table->sections[0].trap_size);
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
                    API::memcpy(&mod->m_phdr_info, iter_info, sizeof(*iter_info));
                    return 1;
                }
            }
            return 0;
        }, this);
    } else {
        API::memcpy(&m_phdr_info, phdr_info, sizeof(*phdr_info));
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

    // FIXME: do we always get .got.plt from the ProgramInfoTable???
    m_got = reinterpret_cast<BytePointer>(m_module_info->program_info_table->got_plt_start);
    // If got_plt_start == m_image_base, that means that
    // _TRaP_got_plt_begin == 0, so we don't have a .got.plt
    // In that case, just use .got as the GOT section
    if (m_got == m_image_base || m_got == nullptr)
      m_got = reinterpret_cast<BytePointer>(m_module_info->program_info_table->got_start);
    RANDO_ASSERT(m_got != nullptr);

    // Some loaders add the image base to the entries in .dynamic, others don't.
    // The easiest way to find out if this is the case is to compare DT_PLTGOT
    // against the address of .got.plt obtained some other way, e.g., from
    // _GLOBAL_OFFSET_TABLE_.
    typedef std::conditional<sizeof(uintptr_t) == 8, Elf64_Dyn, Elf32_Dyn>::type Elf_Dyn;
    auto dyn = reinterpret_cast<Elf_Dyn*>(m_module_info->dynamic);
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_PLTGOT) {
            if (reinterpret_cast<os::BytePointer>(dyn->d_un.d_ptr) == m_got) {
                m_dynamic_has_base = true;
            } else {
                RANDO_ASSERT(RVA2Address(dyn->d_un.d_ptr).to_ptr() == m_got);
                m_dynamic_has_base = false;
            }
            break;
        }
    }

    m_eh_frame_hdr = nullptr;
    for (size_t i = 0; i < m_phdr_info.dlpi_phnum; i++) {
        auto phdr = &m_phdr_info.dlpi_phdr[i];
        if (phdr->p_type == PT_GNU_EH_FRAME) {
            m_eh_frame_hdr = RVA2Address(phdr->p_vaddr).to_ptr();
            break;
        }
    }
    API::debug_printf<1>("Module@%p dynamic:%p PIT:%p base:%p->%p GOT:%p .eh_frame_hdr:%p\n",
                         this, m_module_info->dynamic,
                         m_module_info->program_info_table,
                         m_phdr_info.dlpi_addr, m_image_base, m_got, m_eh_frame_hdr);
    API::debug_printf<1>("Module path:'%s'\n", m_phdr_info.dlpi_name);

    preprocess_arch();
}

RANDO_SECTION Module::~Module() {
    m_arch_relocs.free();
}

RANDO_SECTION void Module::mark_randomized(Module::RandoState state) {
    // TODO: implement
    // TODO: find some unused bit inside the ELF header (somewhere) or phdr
    // FIXME: since we don't support system libraries right now,
    // we don't need to mark the randomized ones (yet)
}

RANDO_SECTION void Module::for_all_exec_sections(bool self_rando, ExecSectionCallback callback, void *callback_arg) {
    // Re-map the read-only segments as RWX
    for (size_t i = 0; i < m_phdr_info.dlpi_phnum; i++) {
        auto phdr = &m_phdr_info.dlpi_phdr[i];
        if ((phdr->p_type == PT_LOAD && (phdr->p_flags & PF_W) == 0)
            || phdr->p_type == PT_GNU_RELRO) {
            auto seg_start = RVA2Address(phdr->p_vaddr).to_ptr();
            auto seg_perms = (phdr->p_flags & PF_X) != 0 ? PagePermissions::RWX
                                                         : PagePermissions::RW;
            API::mprotect(seg_start, phdr->p_memsz, seg_perms);
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
        auto sec_trap_start = reinterpret_cast<BytePointer>(sec_info.trap);
        API::debug_printf<1>("Module@%p sec@%p[%d] TRaP@%p[%d]\n",
                             this, sec_start, sec_info.size,
                             sec_trap_start, sec_info.trap_size);
        Section section(*this, sec_start, sec_info.size);
        TrapInfo sec_trap_info(sec_trap_start, sec_info.trap_size,
                               TRAP_CURRENT_PLATFORM,
                               reinterpret_cast<trap_address_t>(m_got));
        read_got_relocations(&sec_trap_info);
        (*callback)(*this, section, sec_trap_info, self_rando, callback_arg);
        section.flush_icache();
    }
    for (size_t i = 0; i < TRAP_NUM_SECTIONS; i++) {
        auto &sec_info = m_module_info->program_info_table->sections[i];
        // Clear out the trap information fields so we don't wind up
        // trying to randomize multiple times if _TRaP_RandoMain
        // gets called more than once
        sec_info.trap = sec_info.trap_size = 0;
    }
    // Re-map the read-only segments with their original permissions
    for (size_t i = 0; i < m_phdr_info.dlpi_phnum; i++) {
        auto phdr = &m_phdr_info.dlpi_phdr[i];
        if ((phdr->p_type == PT_LOAD && (phdr->p_flags & PF_W) == 0)
            || phdr->p_type == PT_GNU_RELRO) {
            RANDO_ASSERT((phdr->p_flags & PF_R) != 0);
            auto seg_start = RVA2Address(phdr->p_vaddr).to_ptr();
            auto seg_perms = (phdr->p_flags & PF_X) != 0 ? PagePermissions::RX
                                                         : PagePermissions::R;
            API::mprotect(seg_start, phdr->p_memsz, seg_perms);
        }
    }
    // FIXME: if we're not in in-place mode (we moved the copy to a
    // separate region), we should munmap() the original sections
    // to save some space (or at least the memory pages that are
    // entirely contained in those sections)
    //
    // Re-map .xptramp as executable
    auto xptramp_sec = export_section();
    xptramp_sec.flush_icache();
    API::mprotect(xptramp_sec.start().to_ptr(),
                  xptramp_sec.size(),
                  PagePermissions::RX);
}

RANDO_SECTION void Module::for_all_modules(ModuleCallback callback, void *callback_arg) {
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

static RANDO_SECTION int compare_eh_frame_entries(const void *pa, const void *pb) {
    const int32_t *pca = reinterpret_cast<const int32_t*>(pa);
    const int32_t *pcb = reinterpret_cast<const int32_t*>(pb);
    return (pca[0] < pcb[0]) ? -1 : ((pca[0] == pcb[0]) ? 0 : 1);
}

RANDO_SECTION void Module::for_all_relocations(FunctionList *functions) const {
    // Fix up the original entry point and init addresses
    uintptr_t new_dt_init;
    if (m_module_info->program_info_table->orig_dt_init != 0) {
        new_dt_init = m_module_info->program_info_table->orig_dt_init;
        Relocation reloc(*this, &new_dt_init,
                         Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
    } else {
        // Point the branch to the return instruction
        new_dt_init = m_module_info->program_info_table->rando_return;
    }
    // Patch the initial branch to point directly to the relocated function
    Relocation::fixup_entry_point(*this,
                                  m_module_info->program_info_table->rando_init,
                                  new_dt_init);

    uintptr_t new_entry;
    if (m_module_info->program_info_table->orig_entry != 0) {
        new_entry = m_module_info->program_info_table->orig_entry;
        Relocation reloc(*this, &new_entry,
                         Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
    } else {
        // See above
        new_entry = m_module_info->program_info_table->rando_return;
    }
    // Patch the initial branch to point directly to the relocated function
    Relocation::fixup_entry_point(*this,
                                  m_module_info->program_info_table->rando_entry,
                                  new_entry);
    API::debug_printf<1>("New entry:%p init:%p\n", new_dt_init, new_entry);

    relocate_arch(functions);
    if (m_arch_relocs.elems != nullptr) {
        for (size_t i = 0; i < m_arch_relocs.num_elems; i++)
            if (!m_arch_relocs[i].applied) {
                Relocation reloc(*this, m_arch_relocs[i].address,
                                 m_arch_relocs[i].type);
                functions->adjust_relocation(&reloc);
            }
    }

    // Apply relocations to known GOT entries
    for (size_t i = 0; i < m_got_entries.num_elems; i++) {
        API::debug_printf<5>("GOT entry@%p\n", m_got_entries.elems[i]);
        Relocation reloc(*this, m_got_entries.elems[i],
                         Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
    }

    // Fix up .eh_frame_hdr, if it exists
    if (m_eh_frame_hdr != nullptr) {
        uint32_t *ptr = reinterpret_cast<uint32_t*>(m_eh_frame_hdr);
        if (ptr[0] != 0x3b031b01) {
            API::debug_printf<1>("Unknown .eh_frame_hdr encoding: %08x\n", ptr[0]);
        } else {
            uint32_t num_entries = ptr[2];
            API::debug_printf<1>(".eh_frame_hdr found %d entries\n", num_entries);
            for (size_t i = 0, idx = 3; i < num_entries; i++, idx += 2) {
                int32_t entry_pc_delta = static_cast<int32_t>(ptr[idx]);
                BytePointer entry_pc = m_eh_frame_hdr + entry_pc_delta;
                Relocation reloc(*this, &entry_pc,
                                 Relocation::get_pointer_reloc_type());
                functions->adjust_relocation(&reloc);
                ptr[idx] = static_cast<uint32_t>(entry_pc - m_eh_frame_hdr);
            }
            API::qsort(ptr + 3, num_entries, 2 * sizeof(int32_t),
                       compare_eh_frame_entries);
        }
    }
}

template<typename DynType, typename RelType,
         size_t dt_relocs, size_t dt_relocs_size>
RANDO_SECTION void Module::build_arch_relocs() {
#if 0 // Disabled since they overlap with the GOT relocs
    os::BytePointer dyn_rels = nullptr;
    size_t dyn_rel_size = 0;
    auto dyn = reinterpret_cast<DynType*>(m_module_info->dynamic);
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == dt_relocs) {
            if (m_dynamic_has_base) {
                dyn_rels = reinterpret_cast<os::BytePointer>(dyn->d_un.d_ptr);
            } else {
                dyn_rels = m_image_base + dyn->d_un.d_ptr;
            }
        }
        if (dyn->d_tag == dt_relocs_size)
            dyn_rel_size = dyn->d_un.d_val;
    }

    if (dyn_rels != nullptr && dyn_rel_size != 0) {
        auto dyn_rel_end = dyn_rels + dyn_rel_size;
        for (auto rel = reinterpret_cast<Elf64_Rela*>(dyn_rels);
                  rel < reinterpret_cast<Elf64_Rela*>(dyn_rel_end); rel++) {
            auto rel_type = arch_reloc_type(rel);
            if (rel_type) {
                ArchReloc arch_reloc;
                arch_reloc.address = RVA2Address(rel->r_offset).to_ptr();
                arch_reloc.type = rel_type;
                arch_reloc.applied = false;
                m_arch_relocs.append(arch_reloc);
            }
        }
        m_arch_relocs.sort(ArchReloc::sort_compare);
    }
#endif
}

// Instantiate build_arch_relocs() for the most common cases
#if RANDOLIB_ARCH_SIZE == 32
template
RANDO_SECTION void Module::build_arch_relocs<Elf32_Dyn, Elf32_Rel, DT_REL, DT_RELSZ>();
#endif

#if RANDOLIB_ARCH_SIZE == 64
template
RANDO_SECTION void Module::build_arch_relocs<Elf64_Dyn, Elf64_Rela, DT_RELA, DT_RELASZ>();
#endif

RANDO_SECTION Module::ArchReloc *Module::find_arch_reloc(BytePointer address_ptr) const {
    // Given a memory address, find the ArchReloc that covers that address
    // using binary search (assuming the architecture code pre-sorted them)
    if (m_arch_relocs.elems == nullptr) {
        RANDO_ASSERT(m_arch_relocs.num_elems == 0);
        return nullptr;
    }

    // return null if no function contains addr
    if (address_ptr < m_arch_relocs[0].address ||
        address_ptr > m_arch_relocs[m_arch_relocs.num_elems - 1].address)
        return nullptr;
    size_t lo = 0, hi = m_arch_relocs.num_elems - 1;
    while (lo < hi) {
        auto mid = lo + ((hi - lo) >> 1);
        if (address_ptr == m_arch_relocs[mid].address) {
            return const_cast<ArchReloc*>(&m_arch_relocs[mid]);
        } else if (address_ptr > m_arch_relocs[mid].address) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return address_ptr == m_arch_relocs[lo].address
           ? const_cast<ArchReloc*>(&m_arch_relocs[lo])
           : nullptr;
}

RANDO_SECTION void Module::read_got_relocations(const TrapInfo *trap_info) {
    if (m_got_entries.num_elems > 0)
        m_got_entries.free();

    trap_info->for_all_relocations([this] (const trap_reloc_t &trap_reloc) {
        auto reloc = os::Module::Relocation(*this, trap_reloc);
        auto got_entry = reloc.get_got_entry();
        if (got_entry != nullptr)
            m_got_entries.append(got_entry);
    });
    os::API::debug_printf<1>("GOT relocations found: %d\n", m_got_entries.num_elems);
    if (m_got_entries.num_elems == 0)
        return;

    // Sort and eliminate duplicates
    m_got_entries.sort([] (const void *pa, const void *pb) {
        auto *a = reinterpret_cast<const BytePointer*>(pa);
        auto *b = reinterpret_cast<const BytePointer*>(pb);
        return (*a < *b) ? -1 : ((*a == *b) ? 0 : 1);
    });
    m_got_entries.remove_if([this] (size_t idx) {
        return idx > 0 && m_got_entries.elems[idx] == m_got_entries.elems[idx - 1];
    });
    os::API::debug_printf<1>("Final GOT relocations: %d\n",
                             m_got_entries.num_elems);
}

}
