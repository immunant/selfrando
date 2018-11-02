/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2018 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>
#include <RandoLib.h>
#include <TrapInfo.h>

#include <bfdebug.h>
#include <bfplatform.h>

#include <stdarg.h>

extern "C" {
int _TRaP_vsnprintf(char*, size_t, const char*, va_list);
void _TRaP_bfdebug(const char*);
}

namespace os {

#if RANDOLIB_DEBUG_LEVEL_IS_ENV
#ifdef RANDOLIB_DEBUG_LEVEL
int API::debug_level = RANDOLIB_DEBUG_LEVEL;
#else
int API::debug_level = 0;
#endif
#endif

RANDO_SECTION void APIImpl::debug_printf_impl(const char *fmt, ...) {
    char tmp[256];
    va_list args;
    va_start(args, fmt);
    _TRaP_vsnprintf(tmp, 255, fmt, args);
    va_end(args);
    _TRaP_bfdebug(tmp);
}

RANDO_SECTION void API::init() {
#if RANDOLIB_DEBUG_LEVEL_IS_ENV
    const char *debug_level_var = getenv("SELFRANDO_debug_level");
    if (debug_level_var != nullptr)
        debug_level = _TRaP_libc_strtol(debug_level_var, nullptr, 0);
#endif
}

RANDO_SECTION void API::finish() {
    debug_printf<1>("Finished randomizing\n");
}

RANDO_SECTION void *API::mem_alloc(size_t size, bool zeroed) {
    // Since kernels allocate page-aligned blocks anyway,
    // we can ask for page-sized allocations
    size = (size + sizeof(size) + kPageSize - 1) & ~(kPageSize - 1);
    auto res = reinterpret_cast<size_t*>(platform_alloc_rw(size));
    if (res == nullptr)
        return nullptr;
    if (zeroed)
        platform_memset(res, 0, size);

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

    void *res = old_size_ptr;
    if (new_size < old_size) {
        // We're shrinking the region
        auto new_end = reinterpret_cast<BytePointer>(old_size_ptr) + new_size;
        RANDO_ASSERT((reinterpret_cast<uintptr_t>(new_end) & (kPageSize - 1)) == 0);
        platform_free_rw(new_end, old_size - new_size);
        if (new_size == 0)
            return nullptr;
        // Fall-through with res == old_size_ptr
    } else {
        // new_size > old_size
        // We're growing the region
        res = platform_alloc_rw(new_size);
        if (res == nullptr) {
            // Release the old memory, then return an error
            platform_free_rw(old_size_ptr, old_size);
            return nullptr;
        }
        // Copy over the old data, then release the old region
        platform_memcpy(res, old_size_ptr, old_size);
        if (zeroed) {
            auto old_end = reinterpret_cast<BytePointer>(old_size_ptr) + old_size;
            platform_memset(old_end, 0, new_size - old_size);
        }
        platform_free_rw(old_size_ptr, old_size);
    }
    auto new_size_ptr = reinterpret_cast<size_t*>(res);
    *new_size_ptr = new_size;
    return reinterpret_cast<void*>(new_size_ptr + 1);
}

RANDO_SECTION void API::mem_free(void *ptr) {
    auto *size_ptr = reinterpret_cast<size_t*>(ptr);
    size_ptr--;
    platform_free_rw(size_ptr, *size_ptr);
}

RANDO_SECTION void *API::mmap(void *addr, size_t size, PagePermissions perms, bool commit) {
    RANDO_ASSERT(perms == PagePermissions::RW);
    void *res = platform_alloc_rw(size);
    RANDO_ASSERT(addr == nullptr || addr == res);
    if (res != nullptr)
        platform_memset(res, 0, size);
    return res;
}

RANDO_SECTION void API::munmap(void *addr, size_t size, bool commit) {
    platform_free_rw(addr, size);
}

RANDO_SECTION PagePermissions API::mprotect(void *addr, size_t size, PagePermissions perms) {
    // Bareflank doesn't let us do this; all binary pages
    // are RWX during ELF loading
    return PagePermissions::UNKNOWN;
}

RANDO_SECTION File API::open_file(const char *name, bool write, bool create) {
    RANDO_ASSERT(false);
    return kInvalidFile;
}

RANDO_SECTION ssize_t API::write_file(File file, const void *buf, size_t len) {
    RANDO_ASSERT(file != kInvalidFile);
    RANDO_ASSERT(false);
    return 0;
}

RANDO_SECTION void API::close_file(File file) {
    RANDO_ASSERT(file != kInvalidFile);
    RANDO_ASSERT(false);
}

RANDO_SECTION PagePermissions Module::Section::change_permissions(PagePermissions perms) const {
    return PagePermissions::UNKNOWN;
}

RANDO_SECTION Module::Relocation::Relocation(const Module &mod, const trap_reloc_t &reloc)
    : RelocationBase(mod, Address::from_trap(mod, reloc.address).to_ptr(), reloc.type),
      m_symbol_ptr(Address::from_trap(mod, reloc.symbol).to_ptr()), m_addend(reloc.addend) {
    m_has_symbol_ptr = (reloc.symbol != 0); // FIXME: what if zero addresses are legit???
}

RANDO_SECTION Module::Module(Handle bfelf_file)
        : ModuleBase(), m_bfelf_file(bfelf_file) {
    RANDO_ASSERT(m_bfelf_file != nullptr);
    API::debug_printf<1>("Module@%p dynamic:%p base:%p->%p GOT:%p .eh_frame:%p\n",
                         this, m_bfelf_file->dyntab,
                         m_bfelf_file->start_addr,
                         m_bfelf_file->exec_virt,
                         m_bfelf_file->pltgot,
                         m_bfelf_file->eh_frame);
    preprocess_arch();
}

RANDO_SECTION Module::~Module() {
    m_got_entries.clear();
}

RANDO_SECTION void Module::mark_randomized(Module::RandoState state) {
    // Don't care about this (yet) on bareflank
}

RANDO_SECTION void Module::for_all_exec_sections(bool self_rando, ExecSectionCallback callback, void *callback_arg) {
    if (m_bfelf_file->txtrp == 0 ||
        m_bfelf_file->txtrpsz == 0)
        return;

    auto text_start = RVA2Address(m_bfelf_file->text).to_ptr<uintptr_t>();
    auto text_size = m_bfelf_file->textsz;
    auto txtrp_start = RVA2Address(m_bfelf_file->txtrp).to_ptr();
    auto txtrp_size = m_bfelf_file->txtrpsz;
    API::debug_printf<1>("Module@%p text@%p[%d] TRaP@%p[%d]\n",
                         this, text_start, text_size,
                         txtrp_start, txtrp_size);
    Section text(*this, text_start, text_size);
    TrapInfo trap_info(txtrp_start, txtrp_size,
                       TRAP_CURRENT_PLATFORM,
                       reinterpret_cast<trap_address_t>(get_got_ptr()));
    read_got_relocations(&trap_info);
    (*callback)(*this, text, trap_info, self_rando, callback_arg);
    text.flush_icache();
}

RANDO_SECTION void Module::for_all_modules(ModuleCallback callback, void *callback_arg) {
    // TODO: add later
}

RANDO_SECTION void Module::for_all_relocations(FunctionList *functions) const {
    auto fixup_rva = [this, functions] (auto *rva) {
        if (*rva == 0)
            return;
        // FIXME: for now, exec_addr == exec_virt so this magically works
        // however, our whole relocation algorithm breaks if they're not equal
        RANDO_ASSERT(m_bfelf_file->exec_virt == m_bfelf_file->exec_addr);
        uintptr_t addr = reinterpret_cast<uintptr_t>(m_bfelf_file->exec_virt) + *rva;
        Relocation reloc(*this, &addr, Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
        *rva = addr - reinterpret_cast<uintptr_t>(m_bfelf_file->exec_virt);
    };
    API::debug_printf<5>("Relocating entry point(s)\n");
    fixup_rva(&m_bfelf_file->entry);
    fixup_rva(&m_bfelf_file->init);
    fixup_rva(&m_bfelf_file->fini);
    // init_array, fini_array and eh_frame should have relocations in TRaP info
    API::debug_printf<5>("Relocating symbols\n");
    for (size_t i = 0; i < m_bfelf_file->symnum; i++) {
        auto *sym = const_cast<bfelf_sym*>(&m_bfelf_file->symtab[i]);
        fixup_rva(&sym->st_value);
    }

    // FIXME: do we need to apply any dynamic relocations???
    relocate_arch(functions);

    // Apply relocations to known GOT entries
    API::debug_printf<5>("Relocating GOT\n");
    for (auto &ge : m_got_entries) {
        API::debug_printf<5>("GOT entry@%p\n", ge.key());
        Relocation reloc(*this, ge.key(),
                         Relocation::get_pointer_reloc_type());
        functions->adjust_relocation(&reloc);
    }
    API::debug_printf<5>("Finished ELF-specific relocations\n");
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
