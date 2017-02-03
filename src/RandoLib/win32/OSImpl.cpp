/*
 * Copyright (c) 2014-2015, The Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the University of California nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "..\OS.h"
#include "..\TrapInfo.h"

#include <Windows.h>
#include <winternl.h>

#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>

extern "C" {
#include "../util/fnv.h"
}

#pragma comment(lib, "ntdll")
#pragma comment(lib, "kernel32")

// TODO: move these into os::Module
static char kRandoEntrySection[] = ".rndentr";
static char kRandoTextSection[] = ".rndtext";
static char kTrapSection[] = ".txtrp\x00\x00";
static char kExportSection[] = ".xptramp";
static char kRelocSection[] = ".reloc\x00\x00";
static TCHAR kTextrapPathVar[] = TEXT("TEXTRAP_PATH");

namespace os {

// Other Windows globals
HMODULE APIImpl::ntdll, APIImpl::kernel32;
HANDLE APIImpl::global_heap;
LARGE_INTEGER APIImpl::timer_freq;
ULONG APIImpl::rand_seed;

// ntdll functions
ULONG(WINAPI *APIImpl::ntdll_RtlRandomEx)(PULONG);
LONGLONG(WINAPI *APIImpl::ntdll_allmul)(LONGLONG, LONGLONG);
LONGLONG(WINAPI *APIImpl::ntdll_alldiv)(LONGLONG, LONGLONG);
// ntdll functions that implement the C runtime are cdecl, not WINAPI
void(*APIImpl::ntdll_qsort)(void*, size_t, size_t, int(__cdecl*)(const void*, const void*));
int(*APIImpl::ntdll_vsprintf_s)(const char*, ...);
int(*APIImpl::ntdll_memcmp)(const void*, const void*, size_t);
int(*APIImpl::ntdll_memcpy)(void*, const void*, size_t);
int(*APIImpl::ntdll_wcscat_s)(wchar_t*, size_t, const wchar_t*);
int(*APIImpl::ntdll_wcsncat_s)(wchar_t*, size_t, const wchar_t*, size_t);

// kernel32 functions
LPVOID(WINAPI *APIImpl::kernel32_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
BOOL(WINAPI *APIImpl::kernel32_VirtualFree)(LPVOID, SIZE_T, DWORD);
BOOL(WINAPI *APIImpl::kernel32_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
LPVOID(WINAPI *APIImpl::kernel32_HeapAlloc)(HANDLE, DWORD, SIZE_T);
BOOL(WINAPI *APIImpl::kernel32_HeapFree)(HANDLE, DWORD, LPVOID);
HANDLE(WINAPI *APIImpl::kernel32_GetProcessHeap)();
void(WINAPI *APIImpl::kernel32_OutputDebugStringA)(LPCSTR);
HMODULE(WINAPI *APIImpl::kernel32_GetModuleHandleA)(LPCSTR);
bool(WINAPI *APIImpl::kernel32_QueryPerformanceFrequency)(LARGE_INTEGER*);
bool(WINAPI *APIImpl::kernel32_QueryPerformanceCounter)(LARGE_INTEGER*);

// Other functions
int(WINAPI *APIImpl::user32_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

RANDO_SECTION void APIImpl::DebugPrintfImpl(const char *fmt, ...) {
    char tmp[256];
    va_list args;
    va_start(args, fmt);
    ntdll_vsprintf_s(tmp, 255, fmt, args);
    va_end(args);
    kernel32_OutputDebugStringA(tmp);
}

RANDO_SECTION void APIImpl::SystemMessage(const char *fmt, ...) {
    if (user32_MessageBoxA == nullptr)
        return;

    char tmp[256];
    va_list args;
    va_start(args, fmt);
    ntdll_vsprintf_s(tmp, 255, fmt, args);
    va_end(args);
    user32_MessageBoxA(NULL, tmp, "RandoLib", 0);
}

template<typename Func>
static void RANDO_SECTION GetLibFunction(Func *func, HMODULE lib, const char *name) {
    *func = reinterpret_cast<Func>(GetProcAddress(lib, name));
}

RANDO_SECTION void API::Init() {
    ntdll = LoadLibrary(TEXT("ntdll"));
    kernel32 = LoadLibrary(TEXT("kernel32"));
    GetLibFunction(&ntdll_RtlRandomEx, ntdll, "RtlRandomEx");
    GetLibFunction(&ntdll_qsort, ntdll, "qsort");
    GetLibFunction(&ntdll_vsprintf_s, ntdll, "vsprintf_s");
    GetLibFunction(&ntdll_memcmp, ntdll, "memcmp");
    GetLibFunction(&ntdll_memcpy, ntdll, "memcpy");
    GetLibFunction(&ntdll_wcscat_s, ntdll, "wcscat_s");
    GetLibFunction(&ntdll_wcsncat_s, ntdll, "wcsncat_s");
    GetLibFunction(&ntdll_allmul, ntdll, "_allmul");
    GetLibFunction(&ntdll_alldiv, ntdll, "_alldiv");
    GetLibFunction(&kernel32_VirtualAlloc, kernel32, "VirtualAlloc");
    GetLibFunction(&kernel32_VirtualFree, kernel32, "VirtualFree");
    GetLibFunction(&kernel32_VirtualProtect, kernel32, "VirtualProtect");
    GetLibFunction(&kernel32_GetProcessHeap, kernel32, "GetProcessHeap");
    GetLibFunction(&kernel32_HeapAlloc, kernel32, "HeapAlloc");
    GetLibFunction(&kernel32_HeapFree, kernel32, "HeapFree");
    GetLibFunction(&kernel32_OutputDebugStringA, kernel32, "OutputDebugStringA");
    GetLibFunction(&kernel32_GetModuleHandleA, kernel32, "GetModuleHandleA");
    GetLibFunction(&kernel32_QueryPerformanceFrequency, kernel32, "QueryPerformanceFrequency");
    GetLibFunction(&kernel32_QueryPerformanceCounter, kernel32, "QueryPerformanceCounter");
    // TODO: file functions from ReadTrapFile (maybe???)

    if (kEnableAsserts) {
        auto user32 = LoadLibrary(TEXT("user32"));
        GetLibFunction(&user32_MessageBoxA, user32, "MessageBoxA");
        FreeLibrary(user32);
    }

    // TODO: make this optional (a compile-time option)
    // Initialize global constants and values
    global_heap = kernel32_GetProcessHeap();
    kernel32_QueryPerformanceFrequency(&timer_freq);

    // Initialize the seed as a hash of the current TSC (should be random enough)
    // FIXME: find a better way of computing the seed
#ifdef RANDOLIB_DEBUG_SEED
    rand_seed = RANDOLIB_DEBUG_SEED;
#else
    uint64_t tsc = __rdtsc();
    rand_seed = fnv_32a_buf(&tsc, sizeof(tsc), FNV1_32A_INIT);
#endif
}

RANDO_SECTION void API::Finish() {
    FreeLibrary(ntdll);
    FreeLibrary(kernel32);
}


RANDO_SECTION void *API::MemAlloc(size_t size, bool zeroed) {
    DWORD flags = zeroed ? HEAP_ZERO_MEMORY : 0;
    return kernel32_HeapAlloc(global_heap, flags, size);
}

RANDO_SECTION void API::MemFree(void *ptr) {
    kernel32_HeapFree(global_heap, 0, ptr);
}

// WARNING!!!: should be in the same order as the PagePermissions entries
static const DWORD PermissionsTable[] = {
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_READWRITE,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_READWRITE
};

RANDO_SECTION void *API::MemMap(void *addr, size_t size, PagePermissions perms, bool commit) {
    DWORD alloc_type = commit ? (MEM_RESERVE | MEM_COMMIT) : MEM_RESERVE;
    auto win_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    return kernel32_VirtualAlloc(addr, size, alloc_type, win_perms);
}

RANDO_SECTION void API::MemUnmap(void *addr, size_t size, bool commit) {
    if (commit) {
        kernel32_VirtualFree(addr, 0, MEM_RELEASE);
    } else {
        kernel32_VirtualFree(addr, size, MEM_DECOMMIT);
    }
}

RANDO_SECTION PagePermissions API::MemProtect(void *addr, size_t size, PagePermissions perms) {
    DWORD old_win_perms = 0;
    auto win_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    kernel32_VirtualProtect(addr, size, win_perms, &old_win_perms);
    switch (old_win_perms) {
    case PAGE_NOACCESS:
        return PagePermissions::NONE;
    case PAGE_READONLY:
        return PagePermissions::R;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY: // FIXME: is this correct???
        return PagePermissions::RW;
    case PAGE_EXECUTE:
        return PagePermissions::X;
    case PAGE_EXECUTE_READ:
        return PagePermissions::RX;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: // FIXME: is this correct???
        return PagePermissions::RWX;
    default:
        RANDO_ASSERT(false);
        return PagePermissions::NONE;
    }
}

RANDO_SECTION void Module::Address::Reset(const Module &mod, uintptr_t addr, AddressSpace space) {
    RANDO_ASSERT(&mod == &m_module); // We can only reset addresses to the same module
    m_address = addr;
    m_space = space;
}

RANDO_SECTION PagePermissions Module::Section::MemProtect(PagePermissions perms) const {
    if (empty())
        return PagePermissions::NONE;
    return API::MemProtect(m_start.to_ptr(), m_size, perms);
}

RANDO_SECTION Module::Module(Handle info, UNICODE_STRING *name) : m_info(info), m_name(name) {
    RANDO_ASSERT(info != nullptr);
    m_handle = (info->module == nullptr) ? APIImpl::kernel32_GetModuleHandleA(nullptr)
                                         : info->module;
    m_dos_hdr = RVA2Address(0).to_ptr<IMAGE_DOS_HEADER*>();
    m_nt_hdr = RVA2Address(m_dos_hdr->e_lfanew).to_ptr<IMAGE_NT_HEADERS*>();
    m_sections = IMAGE_FIRST_SECTION(m_nt_hdr);
    for (size_t i = 0; i < m_nt_hdr->FileHeader.NumberOfSections; i++) {
        if (API::MemCmp(m_sections[i].Name, kTrapSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
            m_textrap_section = &m_sections[i];
        if (API::MemCmp(m_sections[i].Name, kRelocSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
            m_reloc_section = &m_sections[i];
        if (API::MemCmp(m_sections[i].Name, kExportSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
            m_export_section = &m_sections[i];
    }
    API::DebugPrintf<1>("Module@%p sections .txtrp@%p .reloc@%p .xptramp@%p\n",
                        m_handle, m_textrap_section, m_reloc_section, m_export_section);
}

RANDO_SECTION void Module::MarkRandomized(Module::RandoState state) {
    auto old_perms = API::MemProtect(m_nt_hdr, sizeof(*m_nt_hdr), PagePermissions::RW);
    // FIXME: it would be nice if we had somewhere else to put this, to avoid the copy-on-write
    // LoaderFlags works for now, because it's an obsolete flag (always set to zero)
    m_nt_hdr->OptionalHeader.LoaderFlags = static_cast<DWORD>(state);
    API::MemProtect(m_nt_hdr, sizeof(*m_nt_hdr), old_perms);
}

static RANDO_SECTION bool ReadTrapFile(UNICODE_STRING *module_name,
    BytePointer *textrap_data, size_t *textrap_size) {
#if 0 // FIXME: disabled for now (until I finish the OS layer)
    static const int kTmpMax = 512; // FIXME: large enough???
    TCHAR textrap_file_name[kTmpMax]; // FIXME: stack space???
    auto res = GetEnvironmentVariable(kTextrapPathVar, textrap_file_name, kTmpMax);
    if (!res) {
        // FIXME: just use the current directory for now
        GetCurrentDirectoryW(kTmpMax, textrap_file_name);
    }
    ntdll_wcscat_s(textrap_file_name, kTmpMax, L"\\");
    ntdll_wcsncat_s(textrap_file_name, kTmpMax, module_name->Buffer, module_name->Length);
    ntdll_wcscat_s(textrap_file_name, kTmpMax, L".textrap");

    auto textrap_file = CreateFileW(textrap_file_name, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (textrap_file == INVALID_HANDLE_VALUE) {
        API::DebugPrintf<1>("Error opening textrap file:%d\n", GetLastError());
        return false;
    }

    *textrap_size = GetFileSize(textrap_file, NULL); // FIXME: what if textrap file > 4GB???
    *textrap_data = reinterpret_cast<BytePointer>(API::MemAlloc(*textrap_size));
    if (*textrap_data) {
        DWORD read_bytes = 0;
        auto read_ok = ReadFile(textrap_file, *textrap_data, *textrap_size, &read_bytes, NULL);
        if (read_ok) {
            RANDO_ASSERT(read_bytes == *textrap_size);
            CloseHandle(textrap_file);
            return true;
        }
    }
    CloseHandle(textrap_file);
#endif
    return false;
}

// FIXME: self_rando should be passed as part of callback_arg, not separately
RANDO_SECTION void Module::ForAllExecSections(bool self_rando, ExecSectionCallback callback, void *callback_arg) {
    auto rando_state = m_nt_hdr->OptionalHeader.LoaderFlags;
    bool force_self_rando = (self_rando && rando_state == RandoState::SELF_RANDOMIZE);
    if (rando_state != RandoState::NOT_RANDOMIZED && !force_self_rando)
        return;

    if (m_reloc_section == nullptr) {
        API::DebugPrintf<1>("Error: module not randomized due to missing relocation information.\n");
        MarkRandomized(RandoState::CANT_RANDOMIZE);
        return;
    }

    // FIXME: this could be pre-computed (in the constructor or lazily), and have an accessor
    BytePointer textrap_data = nullptr;
    size_t textrap_size = 0;
    bool release_textrap = false;
    if (m_textrap_section == nullptr) {
        // If we have the textrap info stored in an external file, load it from there
        auto read_ok = ReadTrapFile(m_name, &textrap_data, &textrap_size);
        if (!read_ok) {
            API::DebugPrintf<1>("Error: module not randomized due to missing Trap information.\n");
            MarkRandomized(RandoState::CANT_RANDOMIZE);
            return;
        }
        API::DebugPrintf<1>("Read %d external Trap bytes\n", textrap_size);
        release_textrap = true;
    } else if (!self_rando) {
        // Modules that have a .txtrp section must randomize themselves
        MarkRandomized(RandoState::SELF_RANDOMIZE);
        return;
    } else {
        textrap_data = RVA2Address(m_textrap_section->VirtualAddress).to_ptr();
        textrap_size = m_textrap_section->Misc.VirtualSize;
    }

    // Go through all executable sections and match them against .txtrp
    for (size_t i = 0; i < m_nt_hdr->FileHeader.NumberOfSections; i++) {
        if ((m_sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            if (API::MemCmp(m_sections[i].Name, kRandoEntrySection, IMAGE_SIZEOF_SHORT_NAME) == 0)
                continue; // Skip ".rndentr"
            if (API::MemCmp(m_sections[i].Name, kRandoTextSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
                continue; // Skip ".rndtext"
            if (API::MemCmp(m_sections[i].Name, kExportSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
                continue; // Skip ".xptramp"
            // Found executable section (maybe .text)
            Module::Section exec_section(*this, &m_sections[i]);
            ::TrapInfo trap_info(textrap_data, textrap_size);
            auto xptramp_section = export_section();
            // FIXME: moved the page mapping from ExecSectionProcessor here
            // Still haven't decided if here is better
            auto old_perms = exec_section.MemProtect(PagePermissions::RWX);
            auto old_xptramp_perms = xptramp_section.MemProtect(PagePermissions::RWX);
            (*callback)(*this, exec_section, trap_info, self_rando, callback_arg);
            exec_section.MemProtect(old_perms);
            xptramp_section.MemProtect(old_xptramp_perms);
            // FIXME: call FlushInstructionCache???
        }
    }
    MarkRandomized(RandoState::RANDOMIZED);
    if (release_textrap)
        API::MemFree(textrap_data);
}

RANDO_SECTION void Module::ForAllModules(ModuleCallback callback, void *callback_arg) {
    PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    // Reserved3[1] == ImageBaseAddress
    for (LIST_ENTRY *mod_ptr = peb->Ldr->InMemoryOrderModuleList.Flink; mod_ptr;) {
        LDR_DATA_TABLE_ENTRY *mod_entry = CONTAINING_RECORD(mod_ptr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        auto mod_base_name = reinterpret_cast<UNICODE_STRING*>(mod_entry->Reserved4);
        auto mod_full_name = mod_entry->FullDllName;
        API::DebugPrintf<1>("Module:%p\n", mod_entry->DllBase);
        // TODO: pass in mod_base_name to use in the external .txtrp search
        ModuleInfo mod_info = { NULL, nullptr, mod_entry->DllBase };
        Module mod(&mod_info, mod_base_name);
        (*callback)(mod, callback_arg);
        mod_ptr = mod_entry->InMemoryOrderLinks.Flink;
        if (mod_ptr == &peb->Ldr->InMemoryOrderModuleList)
            break;
    }
}

RANDO_SECTION void Module::ForAllRelocations(FunctionList *functions,
                                             Relocation::Callback callback,
                                             void *callback_arg) const {
    // Fix up the entry point
    if (m_info->new_entry != nullptr) {
        *m_info->new_entry = RVA2Address(m_info->original_entry_rva).to_ptr<uintptr_t>();
        Relocation entry_reloc(*this, address_from_ptr(m_info->new_entry), IMAGE_REL_I386_DIR32);
        (*callback)(entry_reloc, callback_arg);
        API::DebugPrintf<1>("New program entry:%p\n", *m_info->new_entry);
    }
    // Fix up relocations
    RANDO_ASSERT(m_reloc_section != nullptr);
    Section reloc_section(*this, m_reloc_section);
    auto reloc_start = reloc_section.start().to_ptr();
    auto reloc_end = reloc_section.end().to_ptr();
    for (auto block_ptr = reloc_start; block_ptr < reloc_end;) {
        auto fixup_block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(block_ptr);
        auto fixup_addr = RVA2Address(fixup_block->VirtualAddress);
        block_ptr += fixup_block->SizeOfBlock;
        // Pages not inside the current section may be read-only, so un-protect them here
        auto block_old_perms = API::MemProtect(fixup_addr.to_ptr(), kPageSize, PagePermissions::RWX);
        // FIXME: .rndtext contains some of these relocations, so we have to map everything RWX; alternatives???
        for (auto reloc_ptr = reinterpret_cast<WORD*>(fixup_block + 1);
                  reloc_ptr < reinterpret_cast<WORD*>(block_ptr); reloc_ptr++) {
            // Handle one relocation
            // 1) get target of relocation
            auto reloc_type = (*reloc_ptr >> 12),
                reloc_offset = (*reloc_ptr & 0xfff);
            if (reloc_type == IMAGE_REL_BASED_ABSOLUTE)
                continue;
            if (reloc_type != IMAGE_REL_BASED_HIGHLOW) { // TODO: handle this better
                API::DebugPrintf<1>("Unknown relocation type: %d\n", (int)reloc_type);
                continue;
            }
            auto reloc_rva = fixup_block->VirtualAddress + reloc_offset;
            Relocation reloc(*this, RVA2Address(reloc_rva), IMAGE_REL_I386_DIR32);
            (*callback)(reloc, callback_arg);
        }
        API::MemProtect(fixup_addr.to_ptr(), kPageSize, block_old_perms);
    }
}

}
