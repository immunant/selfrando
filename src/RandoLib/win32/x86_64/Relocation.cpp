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

os::Module::Relocation::Relocation(const os::Module &mod, const TrapReloc &reloc)
    : m_module(mod), m_orig_src_addr(mod.address_from_trap(reloc.address)),
    m_src_addr(mod.address_from_trap(reloc.address)), m_type(reloc.type) {
}

os::BytePointer os::Module::Relocation::get_target_ptr() const {
    // IMPORTANT: Keep RandoLib/TrapInfoCommonh.h in sync whenever a new
    // relocation requires a symbol and/or addend.

    auto at_ptr = m_src_addr.to_ptr();
    switch (m_type) {
    case IMAGE_REL_AMD64_ADDR64:
        return reinterpret_cast<os::BytePointer>(*reinterpret_cast<uint64_t*>(at_ptr));
    case IMAGE_REL_AMD64_REL32:
        // We need to use the original address as the source here (not the diversified one)
        // to keep in consistent with the original relocation entry (before shuffling)
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + *reinterpret_cast<int32_t*>(at_ptr);
    case IMAGE_REL_AMD64_REL32_1:
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + 1 + *reinterpret_cast<int32_t*>(at_ptr);
    case IMAGE_REL_AMD64_REL32_2:
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + 2 + *reinterpret_cast<int32_t*>(at_ptr);
    case IMAGE_REL_AMD64_REL32_3:
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + 3 + *reinterpret_cast<int32_t*>(at_ptr);
    case IMAGE_REL_AMD64_REL32_4:
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + 4 + *reinterpret_cast<int32_t*>(at_ptr);
    case IMAGE_REL_AMD64_REL32_5:
        return m_orig_src_addr.to_ptr() + sizeof(int32_t) + 5 + *reinterpret_cast<int32_t*>(at_ptr);
    default:
        return nullptr;
    }
}

void os::Module::Relocation::set_target_ptr(os::BytePointer new_target) {
    auto at_ptr = m_src_addr.to_ptr();
    switch (m_type) {
    case IMAGE_REL_AMD64_ADDR64:
        *reinterpret_cast<uint64_t*>(at_ptr) = reinterpret_cast<uintptr_t>(new_target);
        break;
    case IMAGE_REL_AMD64_REL32:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t)));
        break;
    case IMAGE_REL_AMD64_REL32_1:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t) + 1));
        break;
    case IMAGE_REL_AMD64_REL32_2:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t) + 2));
        break;
    case IMAGE_REL_AMD64_REL32_3:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t) + 3));
        break;
    case IMAGE_REL_AMD64_REL32_4:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t) + 4));
        break;
    case IMAGE_REL_AMD64_REL32_5:
        // FIXME: check for overflow here???
        *reinterpret_cast<int32_t*>(at_ptr) = static_cast<int32_t>(new_target - (at_ptr + sizeof(int32_t) + 5));
        break;
    default:
        RANDO_ASSERT(false);
        break;
    }
}

os::Module::Relocation::Type os::Module::Relocation::get_pointer_reloc_type() {
    return IMAGE_REL_AMD64_ADDR64;
}

os::Module::Relocation::Type
os::Module::Relocation::type_from_based(os::Module::Relocation::Type based_type) {
    if (based_type == IMAGE_REL_BASED_ABSOLUTE)
        return 0;
    if (based_type == IMAGE_REL_BASED_DIR64)
        return IMAGE_REL_AMD64_ADDR64;

    API::DebugPrintf<1>("Unknown relocation type: %d\n", (int) based_type);
    return 0;
}

void os::Module::Relocation::fixup_export_trampoline(BytePointer *export_ptr,
                                                     const Module &module,
                                                     os::Module::Relocation::Callback callback,
                                                     void *callback_arg) {
    RANDO_ASSERT(**export_ptr == 0xE9);
    os::Module::Relocation reloc(module,
                                 module.address_from_ptr(*export_ptr + 1),
                                 IMAGE_REL_AMD64_REL32);
    (*callback)(reloc, callback_arg);
    *export_ptr += 5;
}

extern "C" {
// FIXME: because we add them in here, these get pulled into every binary
// We should find a way to only pull them in when needed
EXCEPTION_DISPOSITION __CxxFrameHandler3(EXCEPTION_RECORD*, void*, CONTEXT*, DISPATCHER_CONTEXT*);
EXCEPTION_DISPOSITION __GSHandlerCheck(EXCEPTION_RECORD*, void*, CONTEXT*, DISPATCHER_CONTEXT*);
EXCEPTION_DISPOSITION __GSHandlerCheck_SEH(EXCEPTION_RECORD*, void*, CONTEXT*, DISPATCHER_CONTEXT*);
EXCEPTION_DISPOSITION __GSHandlerCheck_EH(EXCEPTION_RECORD*, void*, CONTEXT*, DISPATCHER_CONTEXT*);
}

void os::Module::arch_init() {
    seh_C_specific_handler_rva  = reinterpret_cast<uintptr_t>(__C_specific_handler) -
                                  reinterpret_cast<uintptr_t>(m_handle);
    seh_CxxFrameHandler3_rva    = reinterpret_cast<uintptr_t>(__CxxFrameHandler3) -
                                  reinterpret_cast<uintptr_t>(m_handle);
#if 0
    // For now, we don't care about this one
    seh_GSHandlerCheck_rva      = reinterpret_cast<uintptr_t>(__GSHandlerCheck) -
                                  reinterpret_cast<uintptr_t>(m_handle);
#endif
    seh_GSHandlerCheck_SEH_rva  = reinterpret_cast<uintptr_t>(__GSHandlerCheck_SEH) -
                                  reinterpret_cast<uintptr_t>(m_handle);
    seh_GSHandlerCheck_EH_rva   = reinterpret_cast<uintptr_t>(__GSHandlerCheck_EH) -
                                  reinterpret_cast<uintptr_t>(m_handle);
}

// We have to define our own, since Windows doesn't have it
struct UNWIND_INFO {
    uint8_t version : 3;
    uint8_t flags : 5;
    uint8_t prolog_size;
    uint8_t num_codes;
    uint8_t frame_reg : 4;
    uint8_t frame_offset : 4;
    uint16_t codes[1];
};

#define FUNC_INFO_MAGIC_MIN     0x19930520
#define FUNC_INFO_MAGIC_MAX     0x19930522

struct FuncInfo {
    uint32_t magic;
    uint32_t num_states;
    uint32_t unwind_map_rva;
    uint32_t num_try_blocks;
    uint32_t try_block_map_rva;
    uint32_t num_ip_state_map_entries;
    uint32_t ip_state_map_rva;
};

struct UnwindMapEntry {
    int32_t state;
    uint32_t handler_rva;
};

struct CatchBlock {
    uint32_t flags;
    uint32_t type_rva;
    int32_t object;
    uint32_t handler_rva;
};

struct TryBlock {
    int32_t try_low;
    int32_t try_high;
    int32_t catch_level;
    int32_t num_catches;
    uint32_t catches_rva;
};

struct IpStateMapEntry {
    uint32_t ip_rva;
    int32_t state;
};

static RANDO_SECTION int compare_first_dword(const void *pa, const void *pb) {
    auto *fa = reinterpret_cast<const DWORD*>(pa);
    auto *fb = reinterpret_cast<const DWORD*>(pb);
    return (fa[0] < fb[0]) ? -1 : 1;
}

void os::Module::fixup_target_relocations(FunctionList *functions,
                                          Relocation::Callback callback,
                                          void *callback_arg) const {
    for (size_t i = 0; i < functions->num_funcs; i++) {
        auto &func = functions->functions[i];
        if (func.from_trap)
            continue;
        RANDO_ASSERT(func.is_gap); // Functions should either be from TRaP info or gaps

        auto div_ptr = func.div_start;
        auto undiv_ptr = func.undiv_start;
        // Look for PC-relative indirect branches
        // FIXME: we do this to find the 6-byte import trampolines
        // inserted by the linker; they're not in TRaP info, so
        // we need to scan for them manually.
        // WARNING!!!: we may get false positives
        for (;;) {
            while (div_ptr < func.div_end() &&
                (div_ptr[0] == 0xCC || div_ptr[0] == 0x90))
                div_ptr++, undiv_ptr++;

            if (div_ptr + 6 > func.div_end())
                break;
            if (div_ptr[0] != 0xFF || div_ptr[1] != 0x25)
                break;

            os::API::DebugPrintf<10>("Found import trampoline @%p/%p\n",
                                     undiv_ptr, div_ptr);
            os::Module::Relocation reloc(*this,
                                         address_from_ptr(undiv_ptr + 2),
                                         IMAGE_REL_AMD64_REL32);
            (*callback)(reloc, callback_arg);
            div_ptr += 6;
            undiv_ptr += 6;
        }
    }
    // Update the exception handling metadata
    if (IMAGE_DIRECTORY_ENTRY_EXCEPTION < m_nt_hdr->OptionalHeader.NumberOfRvaAndSizes) {
        auto &exception_dir = m_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exception_dir.VirtualAddress != 0 && exception_dir.Size > 0) {
            auto pdata_start = RVA2Address(exception_dir.VirtualAddress).to_ptr<RUNTIME_FUNCTION*>();
            auto pdata_end = RVA2Address(exception_dir.VirtualAddress + exception_dir.Size).to_ptr<RUNTIME_FUNCTION*>();
            os::API::DebugPrintf<2>("Found .pdata:%p-%p\n", pdata_start, pdata_end);
            // FIXME: .obj files have ADDR32NB relocations for all the function pointers we care about
            // Instead of parsing all these structures manually, we could add those ADDR32NB relocations
            // to TRaP info and handle them in get/set_target_ptr above. However, that would mean
            // we would have to add TRaP records for all .pdata/.xdata/other EH-related sections
            for (auto *ptr = pdata_start; ptr < pdata_end; ptr++) {
                relocate_rva(&ptr->BeginAddress, callback, callback_arg, false);
                relocate_rva(&ptr->EndAddress, callback, callback_arg, true);
                if (ptr->UnwindInfoAddress & 1)
                    continue;

                auto unwind_info = RVA2Address(ptr->UnwindInfoAddress).to_ptr<UNWIND_INFO*>();
                if (unwind_info->version != 1) {
                    os::API::DebugPrintf<1>("Unknown UNWIND_INFO version:%d\n",
                                            static_cast<int32_t>(unwind_info->version));
                    continue;
                }

                auto end_of_codes = &unwind_info->codes[unwind_info->num_codes + (unwind_info->num_codes & 1)];
                if (unwind_info->flags & UNW_FLAG_CHAININFO) {
                    // We have a chained RUNTIME_FUNCTION
                    auto *chain = reinterpret_cast<RUNTIME_FUNCTION*>(end_of_codes);
                    relocate_rva(&chain->BeginAddress, callback, callback_arg, false);
                    relocate_rva(&chain->EndAddress, callback, callback_arg, true);
                } else if (unwind_info->flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
                    auto handler_rva_ptr = reinterpret_cast<DWORD*>(end_of_codes);
                    auto handler_rva = *handler_rva_ptr;
                    auto lsda_ptr = reinterpret_cast<os::BytePointer>(handler_rva_ptr + 1);
                    relocate_rva(handler_rva_ptr, callback, callback_arg, false);
#if 0
                    if (*handler_rva_ptr == seh_GSHandlerCheck_rva ||
                        *handler_rva_ptr == seh_GSHandlerCheck_SEH_rva) {
                        // If we ever need to relocate GS cookie data, do it here
                        // For now, we don't need to do anything
                    }
#endif
                    if (handler_rva == seh_C_specific_handler_rva ||
                        handler_rva == seh_GSHandlerCheck_SEH_rva) {
                        auto *scope_table = reinterpret_cast<SCOPE_TABLE_AMD64*>(lsda_ptr);
                        os::API::DebugPrintf<2>("Scope table:%p[%d]\n",
                                                scope_table, scope_table->Count);
                        for (size_t i = 0; i < scope_table->Count; i++) {
                            auto &scope_record = scope_table->ScopeRecord[i];
                            relocate_rva(&scope_record.BeginAddress, callback, callback_arg, false);
                            relocate_rva(&scope_record.EndAddress, callback, callback_arg, true);
                            // HandlerAddress can have the special values 0 or 1, which
                            // we should ignore
                            if (scope_record.HandlerAddress > 1)
                                relocate_rva(&scope_record.HandlerAddress, callback, callback_arg, false);
                            if (scope_record.JumpTarget != 0)
                                relocate_rva(&scope_record.JumpTarget, callback, callback_arg, false);
                        }
                        // Re-sort the contents of pdata
                        os::API::QuickSort(&scope_table->ScopeRecord[0],
                                           scope_table->Count,
                                           sizeof(SCOPE_TABLE_AMD64::ScopeRecord[0]),
                                           compare_first_dword);
                    }
                    if (handler_rva == seh_CxxFrameHandler3_rva ||
                        handler_rva == seh_GSHandlerCheck_EH_rva) {
                        auto func_info_rva = *reinterpret_cast<uint32_t*>(lsda_ptr);
                        auto *func_info = RVA2Address(func_info_rva).to_ptr<FuncInfo*>();
                        if (func_info->magic < FUNC_INFO_MAGIC_MIN ||
                            func_info->magic > FUNC_INFO_MAGIC_MAX) {
                            os::API::DebugPrintf<1>("Unknown FuncInfo magic:%d\n", func_info->magic);
                            continue;
                        }
                        if (func_info->unwind_map_rva != 0) {
                            auto *unwind_map = RVA2Address(func_info->unwind_map_rva).to_ptr<UnwindMapEntry*>();
                            for (size_t i = 0; i < func_info->num_states; i++)
                                relocate_rva(&unwind_map[i].handler_rva, callback, callback_arg, false);
                        }
                        if (func_info->try_block_map_rva != 0) {
                            auto *try_block_map = RVA2Address(func_info->try_block_map_rva).to_ptr<TryBlock*>();
                            for (size_t i = 0; i < func_info->num_try_blocks; i++) {
                                auto &try_block = try_block_map[i];
                                if (try_block.catches_rva != 0) {
                                    auto *catches = RVA2Address(try_block.catches_rva).to_ptr<CatchBlock*>();
                                    for (size_t j = 0; j < try_block.num_catches; j++) {
                                        relocate_rva(&catches[j].handler_rva, callback, callback_arg, false);
                                        // TODO: do we need to follow type_rva???
                                    }
                                }
                            }
                        }
                        if (func_info->ip_state_map_rva != 0) {
                            auto *ip_state_map = RVA2Address(func_info->ip_state_map_rva).to_ptr<IpStateMapEntry*>();
                            for (size_t i = 0; i < func_info->num_ip_state_map_entries; i++)
                                relocate_rva(&ip_state_map[i].ip_rva, callback, callback_arg, false);
                            // The ip_state_map needs to be sorted
                            os::API::QuickSort(ip_state_map,
                                               func_info->num_ip_state_map_entries,
                                               sizeof(IpStateMapEntry),
                                               compare_first_dword);
                        }
                    }
                }
            }
            // Re-sort the contents of pdata
            os::API::QuickSort(pdata_start,
                               pdata_end - pdata_start,
                               sizeof(RUNTIME_FUNCTION),
                               compare_first_dword);
        }
    }
}
