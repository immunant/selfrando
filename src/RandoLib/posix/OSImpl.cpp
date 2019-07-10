/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
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

void *_TRaP_syscall_mmap(void*, size_t, int, int, int, off_t);
void *_TRaP_syscall_mremap(void*, size_t, size_t, int, ...);
int _TRaP_syscall_munmap(void*, size_t);
int _TRaP_syscall_mprotect(const void*, size_t, int);
int _TRaP_syscall_unlinkat(int, const char*, int);

void _TRaP_rand_close_fd(void);
}

#if RANDOLIB_RNG_IS_CHACHA
void _TRaP_chacha_init_urandom(void);
void _TRaP_chacha_finish(void);
#endif

namespace os {

#if RANDOLIB_RNG_IS_RAND_R
uint32_t APIImpl::rand_seed[RANDOLIB_SEED_WORDS] = {0};
#endif

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
    _TRaP_syscall_write(2, tmp, len);
#elif RANDOLIB_LOG_TO_FILE || RANDOLIB_LOG_TO_DEFAULT
    if (log_fd > 0)
        _TRaP_syscall_write(log_fd, tmp, len);
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
    log_fd = _TRaP_syscall_open(STRINGIFY_MACRO(RANDOLIB_LOG_FILENAME), log_flags, 0660);
#undef STRINGIFY
#undef STRINGIFY_MACRO
#endif

#if RANDOLIB_RNG_IS_CHACHA
    _TRaP_chacha_init_urandom();
#elif RANDOLIB_RNG_IS_RAND_R
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
        _TRaP_syscall____close(log_fd);
#endif

#if RANDOLIB_RNG_IS_CHACHA
    _TRaP_chacha_finish();
#elif RANDOLIB_RNG_IS_RAND_R
    for (size_t i = 0; i < RANDOLIB_SEED_WORDS; i++)
        rand_seed[i] = 0;
#elif RANDOLIB_RNG_IS_URANDOM
    _TRaP_rand_close_fd();
#else
#error Unknown RNG setting
#endif
}


RANDO_SECTION void *API::mem_alloc(size_t size, bool zeroed) {
    size = (size + sizeof(size) + kPageSize - 1) & ~(kPageSize - 1);
    auto res = reinterpret_cast<size_t*>(_TRaP_syscall_mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (APIImpl::syscall_retval_is_err(res))
        return nullptr;

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
    new_size = (new_size + sizeof(new_size) + kPageSize - 1) & ~(kPageSize - 1);
    if (new_size == old_size)
        return old_ptr;

    void *res = nullptr;
#if RANDOLIB_NO_MREMAP
    if (new_size < old_size) {
        // We're shrinking the region
        auto new_end = reinterpret_cast<BytePointer>(old_size_ptr) + new_size;
        _TRaP_syscall_munmap(new_end, old_size - new_size);
        if (new_size > 0) {
            *old_size_ptr = new_size;
            return reinterpret_cast<void*>(old_size_ptr + 1);
        }
        return nullptr;
    } else {
        // new_size > old_size
        // We're growing the region
        // First, try to just mmap in the extra pages at the end
        // We're going to try to mmap() some pages at the end of
        // the old region, and see if the kernel gives them to us
        auto old_end = reinterpret_cast<BytePointer>(old_size_ptr) + old_size;
        auto size_delta = new_size - old_size;
        res = _TRaP_syscall_mmap(old_end, size_delta,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS,
                                 -1, 0);
        if (!APIImpl::syscall_retval_is_err(res)) {
            if (res == old_end) {
                *old_size_ptr = new_size;
                return reinterpret_cast<void*>(old_size_ptr + 1);
            } else {
                // We got a valid mapping, but at the wrong address
                // Unmap it before proceeding
                _TRaP_syscall_munmap(res, size_delta);
            }
        }
        // We couldn't get the region we wanted, so fall back to
        // allocating a whole new region the copying the old data over
        res = _TRaP_syscall_mmap(nullptr, new_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS,
                                 -1, 0);
        if (APIImpl::syscall_retval_is_err(res)) {
            // Release the old memory, then return an error
            _TRaP_syscall_munmap(old_size_ptr, old_size);
            return nullptr;
        }
        // Copy over the old data, then release the old region
        API::memcpy(res, old_size_ptr, old_size);
        _TRaP_syscall_munmap(old_size_ptr, old_size);
    }
#else
    res = _TRaP_syscall_mremap(old_size_ptr, old_size,
                               new_size, MREMAP_MAYMOVE);
    if (APIImpl::syscall_retval_is_err(res))
        return nullptr;
#endif

    auto new_size_ptr = reinterpret_cast<size_t*>(res);
    *new_size_ptr = new_size;
    return reinterpret_cast<void*>(new_size_ptr + 1);
}

RANDO_SECTION void API::mem_free(void *ptr) {
    auto *size_ptr = reinterpret_cast<size_t*>(ptr);
    size_ptr--;
    _TRaP_syscall_munmap(size_ptr, *size_ptr);
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
    auto new_addr =_TRaP_syscall_mmap(addr, size, prot_perms, flags, -1, 0);
    return APIImpl::syscall_retval_is_err(new_addr) ? nullptr : new_addr;
}

RANDO_SECTION void API::munmap(void *addr, size_t size, bool commit) {
    _TRaP_syscall_munmap(addr, size);
}

RANDO_SECTION PagePermissions API::mprotect(void *addr, size_t size, PagePermissions perms) {
    RANDO_ASSERT(perms != PagePermissions::UNKNOWN);
    int prot_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    auto paged_addr = (reinterpret_cast<uintptr_t>(addr) & ~(kPageSize - 1));
    auto paged_size = (reinterpret_cast<uintptr_t>(addr) + size) - paged_addr;
    _TRaP_syscall_mprotect(reinterpret_cast<void*>(paged_addr), paged_size, prot_perms);
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
    int fd = _TRaP_syscall_open(name, flags, 0660);
    return APIImpl::syscall_retval_is_err(fd) ? kInvalidFile : fd;
}

RANDO_SECTION ssize_t API::read_file(File file, void *buf, size_t len) {
    RANDO_ASSERT(file != kInvalidFile);
    return _TRaP_syscall_read(file, buf, len);
}

RANDO_SECTION ssize_t API::write_file(File file, const void *buf, size_t len) {
    RANDO_ASSERT(file != kInvalidFile);
    return _TRaP_syscall_write(file, buf, len);
}

RANDO_SECTION void API::close_file(File file) {
    RANDO_ASSERT(file != kInvalidFile);
    _TRaP_syscall____close(file);
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
RANDO_PUBLIC_FUNCTION(selfrando_delete_layout_file, void, void) {
    // TODO: don't delete if disabled via environment variable
    char filename[32];
    build_pid_filename(filename, "/tmp/%d.mlf", API::getpid());
    _TRaP_syscall_unlinkat(AT_FDCWD, filename, 0);
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
        : ModuleBase(), m_module_info(module_info),
          m_module_name("<module>") {
    RANDO_ASSERT(m_module_info != nullptr);
    convert_phdr_info(phdr_info);

    // FIXME: do we always get .got.plt from the ModuleInfo???
    m_got = reinterpret_cast<BytePointer>(m_module_info->got_start);
    RANDO_ASSERT(m_got != nullptr);

    m_eh_frame_hdr = nullptr;
    for (size_t i = 0; i < m_phnum; i++) {
        if (m_phdr[i].p_type == PT_GNU_EH_FRAME) {
            m_eh_frame_hdr = RVA2Address(m_phdr[i].p_vaddr).to_ptr();
            break;
        }
    }

    API::debug_printf<1>("Module@%p base:%p GOT:%p .eh_frame_hdr:%p\n",
                         this, m_image_base, m_got, m_eh_frame_hdr);
    API::debug_printf<1>("Module path:'%s'\n", m_module_name);
    os::API::debug_printf<5>("Module info:\n");
    os::API::debug_printf<5>("  args: %p\n", m_module_info->args);
    os::API::debug_printf<5>("  orig_dt_init: %p\n", m_module_info->orig_dt_init);
    os::API::debug_printf<5>("  orig_entry: %p\n", m_module_info->orig_entry);
    os::API::debug_printf<5>("  dynamic: %p\n", m_module_info->dynamic);
    os::API::debug_printf<5>("  xptramp: %p (%u)\n", m_module_info->xptramp_start,
                             m_module_info->xptramp_size);
    os::API::debug_printf<5>("  text: %p (%u)\n", m_module_info->sections[0].start,
                             m_module_info->sections[0].size);
    os::API::debug_printf<5>("  trap: %p (%u)\n", m_module_info->sections[0].trap,
                             m_module_info->sections[0].trap_size);

    preprocess_arch();
}

RANDO_SECTION Module::~Module() {
    m_got_entries.clear();
}

RANDO_SECTION void Module::convert_phdr_info(PHdrInfoPointer phdr_info) {
    // We need to convert the ELF PHdr module information into our own format
    // We have 3 possible sources:
    // 1) the `phdr_info` argument passed to the constructor
    // 2) the auxiliary vector from the kernel, if we have it
    // 3) `dl_iterate_phdr`, as a last resort
    // Option 1: try `phdr_info`
    if (phdr_info != nullptr) {
        m_image_base = phdr_info->dlpi_addr;
        m_phdr = phdr_info->dlpi_phdr;
        m_phnum = phdr_info->dlpi_phnum;
        m_module_name = phdr_info->dlpi_name;
        return;
    }

    // Option 2: scan the auxiliary vector
    if (m_module_info->args != nullptr) {
        auto p = m_module_info->args;
        auto argc = *p++;
        // Skip over argv
        m_module_name = reinterpret_cast<const char*>(*p++);
        p += argc;
        // Skip over envp
        while (*p)
            p++;

        bool found_phdr = false,
             found_phnum = false;
        auto auxv = reinterpret_cast<RANDOLIB_ELF(auxv_t)*>(++p);
        for (; auxv->a_type != AT_NULL; auxv++) {
            os::API::debug_printf<10>("AUXV[%p]=%p\n",
                                      auxv->a_type, auxv->a_un.a_val);
            switch (auxv->a_type) {
            case AT_ENTRY:
                RANDO_ASSERT(auxv->a_un.a_val == m_module_info->selfrando_entry);
                break;

            case AT_PHDR:
                m_phdr = reinterpret_cast<const RANDOLIB_ELF(Phdr)*>(auxv->a_un.a_val);
                found_phdr = true;
                break;

            case AT_PHENT:
                RANDO_ASSERT(auxv->a_un.a_val == sizeof(RANDOLIB_ELF(Phdr)));
                break;

            case AT_PHNUM:
                m_phnum = auxv->a_un.a_val;
                found_phnum = true;
                break;
            }
        }

        if (found_phdr && found_phnum) {
            // Find the image base (address of the first file byte)
            // FIXME: is this 100% correct???
            m_image_base = 0;
            // Try to extract the image base for the PT_PHDR header;
            // if we can't find it, then it's very likely that the binary
            // hasn't been moved, and the image base is 0
            for (size_t i = 0; i < m_phnum; i++) {
                if (m_phdr[i].p_type == PT_PHDR) {
                    m_image_base = reinterpret_cast<uintptr_t>(m_phdr) - m_phdr[i].p_vaddr;
                    break;
                } else if (m_phdr[i].p_type == PT_DYNAMIC) {
                    m_image_base = reinterpret_cast<uintptr_t>(m_module_info->dynamic) -
                        m_phdr[i].p_vaddr;
                    break;
                }
            }
            return;
        }
    }

    // Option 3: iterate thru the phdr's to find the one for our .text section
    dl_iterate_phdr([] (PHdrInfoPointer iter_info, size_t size, void *arg) {
        Module *mod = reinterpret_cast<Module*>(arg);
        auto mod_text = mod->m_module_info->sections[0].start;
        for (size_t i = 0; i < iter_info->dlpi_phnum; i++) {
            auto phdr = &iter_info->dlpi_phdr[i];
            auto phdr_start = static_cast<uintptr_t>(iter_info->dlpi_addr + phdr->p_vaddr);
            auto phdr_end = phdr_start + phdr->p_memsz;
            if (phdr->p_type == PT_LOAD &&
                mod_text >= phdr_start && mod_text < phdr_end) {
                mod->convert_phdr_info(iter_info);
                return 1;
            }
        }
        return 0;
    }, this);
}

RANDO_SECTION void Module::mark_randomized(Module::RandoState state) {
    // TODO: implement
    // TODO: find some unused bit inside the ELF header (somewhere) or phdr
    // FIXME: since we don't support system libraries right now,
    // we don't need to mark the randomized ones (yet)
}

RANDO_SECTION void Module::for_all_exec_sections(bool self_rando, ExecSectionCallback callback, void *callback_arg) {
    // Re-map the read-only segments as RWX
    for (size_t i = 0; i < m_phnum; i++) {
        if ((m_phdr[i].p_type == PT_LOAD && (m_phdr[i].p_flags & PF_W) == 0) ||
            m_phdr[i].p_type == PT_GNU_RELRO) {
            auto seg_start = RVA2Address(m_phdr[i].p_vaddr).to_ptr();
            auto seg_perms = (m_phdr[i].p_flags & PF_X) != 0 ? PagePermissions::RWX
                                                             : PagePermissions::RW;
            API::mprotect(seg_start, m_phdr[i].p_memsz, seg_perms);
        }
    }
    // FIXME: unfortunately, the loader doesn't seem to load
    // the section table into memory (it's outside the PT_LOAD segments).
    // For this reason, we need to get the executable sections from somewhere
    // else. Currently, PatchEntry takes care of this.
    for (size_t i = 0; i < TRAP_NUM_SECTIONS; i++) {
        auto &sec_info = m_module_info->sections[i];
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
        auto &sec_info = m_module_info->sections[i];
        // Clear out the trap information fields so we don't wind up
        // trying to randomize multiple times if _TRaP_RandoMain
        // gets called more than once
        sec_info.trap = sec_info.trap_size = 0;
    }
    // Re-map the read-only segments with their original permissions
    for (size_t i = 0; i < m_phnum; i++) {
        if ((m_phdr[i].p_type == PT_LOAD && (m_phdr[i].p_flags & PF_W) == 0) ||
            m_phdr[i].p_type == PT_GNU_RELRO) {
            RANDO_ASSERT((m_phdr[i].p_flags & PF_R) != 0);
            auto seg_start = RVA2Address(m_phdr[i].p_vaddr).to_ptr();
            auto seg_perms = (m_phdr[i].p_flags & PF_X) != 0 ? PagePermissions::RX
                                                             : PagePermissions::R;
            API::mprotect(seg_start, m_phdr[i].p_memsz, seg_perms);
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
    // that don't provide a m_module_info-> and the ones
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
    if (m_module_info->orig_dt_init != 0) {
        new_dt_init = m_module_info->orig_dt_init;
        Relocation reloc(*this, &new_dt_init,
                         Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
    } else {
        // Point the branch to the return instruction
        new_dt_init = m_module_info->selfrando_return;
    }
    // Patch the initial branch to point directly to the relocated function
    Relocation::fixup_entry_point(*this,
                                  m_module_info->selfrando_init,
                                  new_dt_init);

    uintptr_t new_entry;
    if (m_module_info->orig_entry != 0) {
        new_entry = m_module_info->orig_entry;
        Relocation reloc(*this, &new_entry,
                         Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
    } else {
        // See above
        new_entry = m_module_info->selfrando_return;
    }
    // Patch the initial branch to point directly to the relocated function
    Relocation::fixup_entry_point(*this,
                                  m_module_info->selfrando_entry,
                                  new_entry);
    API::debug_printf<1>("New init:%p entry:%p\n", new_dt_init, new_entry);

    // Fixup our preinit function
    Relocation::fixup_entry_point(*this, m_module_info->selfrando_preinit,
                                  m_module_info->selfrando_return);

    relocate_arch(functions);

    // Apply relocations to known GOT entries
    for (auto &ge : m_got_entries) {
        API::debug_printf<5>("GOT entry@%p\n", ge.key());
        Relocation reloc(*this, ge.key(),
                         Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
    }

    // Fix up .eh_frame_hdr, if it exists
    if (m_eh_frame_hdr != nullptr) {
        uint32_t *ptr = reinterpret_cast<uint32_t*>(m_eh_frame_hdr);
        if (ptr[0] != 0x3b031b01) {
            API::debug_printf<1>("Unknown .eh_frame_hdr encoding: %x\n", ptr[0]);
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

RANDO_SECTION void Module::read_got_relocations(const TrapInfo *trap_info) {
    trap_info->for_all_relocations([this] (const trap_reloc_t &trap_reloc) {
        auto reloc = os::Module::Relocation(*this, trap_reloc);
        auto got_entry = reloc.get_got_entry();
        if (got_entry != nullptr)
            m_got_entries.insert(got_entry);
    });
    os::API::debug_printf<1>("GOT relocations found: %d\n",
                             m_got_entries.elements());
}

}
