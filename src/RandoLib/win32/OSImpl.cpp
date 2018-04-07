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

#define _CRT_NO_VA_START_VALIDATION // Disable this since it puts __vcrt_va_start_verify_argument_type() in .text

#include <OS.h>
#include <RandoLib.h>
#include <TrapInfo.h>

#include <Windows.h>
#include <winternl.h>

#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>

extern "C" {
#include <util/fnv.h>

int _TRaP_vsnprintf(char*, size_t, const char*, va_list);
long _TRaP_libc_strtol(const char*, char **, int);
}

#pragma comment(lib, "ntdll")
#pragma comment(lib, "kernel32")

// We have an unintended dependency on operator delete (void *), which in turn depends on _free.
// If the latter is not provided by the C library (if the randomized program is linked with the
// "/NODEFAULTLIB:LIBC" option), we need to provide a placeholder so the linker stops complaining
extern "C" const char *TRaP_free_placeholder = nullptr;
#pragma comment(linker, "/alternatename:_free=_TRaP_free_placeholder")

// TODO: move these into os::Module
static const char kRandoEntrySection[] = ".rndentr";
static const char kRandoTextSection[] = ".rndtext";
static const char kTrapSection[] = ".txtrp\x00\x00";
static const char kExportSection[] = ".xptramp";
static const char kRelocSection[] = ".reloc\x00\x00";
static const TCHAR kTextrapPathVar[] = TEXT("TEXTRAP_PATH");

extern "C" {
// We need to store the pointer to VirtualProtect somewhere for a bit of time
void *__TRaP_VirtualProtect_ptr;
void *__TRaP_rndtext_address;
size_t __TRaP_rndtext_size;
};

namespace os {

// Other Windows globals
HMODULE APIImpl::ntdll, APIImpl::kernel32;
LARGE_INTEGER APIImpl::timer_freq;
uint32_t APIImpl::rand_seed[RANDOLIB_SEED_WORDS] = {};

// Buffer that holds the return values for environment variables
// We need to hold it in a global variable, since getenv callers may hold
// it indefinitely (WARNING: although they can't hold it past the next call)
// We can't just store a Buffer<char> object here, since that makes
// the compiler emit a dynamic initializer for it in a ".text$di" section
// and add a call to atexit() for the object's destructor
Buffer<char> *APIImpl::env_buf;

#define SYS_FUNCTION(library, name, API, result_type, ...)   result_type (API *APIImpl::library##_##name)(__VA_ARGS__);
#include "SysFunctions.inc"
#undef SYS_FUNCTION

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
    RANDO_SYS_FUNCTION(kernel32, OutputDebugStringA, tmp);
}

RANDO_SECTION void APIImpl::SystemMessage(const char *fmt, ...) {
    if (user32_MessageBoxA == nullptr)
        return;

    char tmp[256];
    va_list args;
    va_start(args, fmt);
    _TRaP_vsnprintf(tmp, 255, fmt, args);
    va_end(args);
    RANDO_SYS_FUNCTION(user32, MessageBoxA, NULL, tmp, "RandoLib", 0);
}

static RANDO_SECTION inline bool cpu_has_rdseed() {
    int cpu_info[4];
    __cpuid(cpu_info, 7);
    return (cpu_info[1] & 0x40000) != 0;
}

RANDO_SECTION void API::init() {
    ntdll = LoadLibrary(TEXT("ntdll"));
    kernel32 = LoadLibrary(TEXT("kernel32"));
    HMODULE user32 = kEnableAsserts ? LoadLibrary(TEXT("user32")) : nullptr;

#define SYS_FUNCTION(library, name, API, result_type, ...)  \
    if (library != nullptr) {                               \
        auto func_addr = GetProcAddress(library, #name);    \
        library##_##name = reinterpret_cast<decltype(library##_##name)>(func_addr); \
    } else {                                                \
        library##_##name = nullptr;                         \
    }
#include "SysFunctions.inc"
#undef SYS_FUNCTION

    // FIXME: should we keep this around until API::Finish???
    if (user32 != nullptr)
        FreeLibrary(user32);

#if RANDOLIB_DEBUG_LEVEL_IS_ENV
    const char *debug_level_var = API::getenv("SELFRANDO_debug_level");
    if (debug_level_var != nullptr)
        debug_level = _TRaP_libc_strtol(debug_level_var, nullptr, 0);
#endif

    // TODO: make this optional (a compile-time option)
    // Initialize global constants and values
    RANDO_SYS_FUNCTION(kernel32, QueryPerformanceFrequency, &timer_freq);

    // Initialize the seed as a hash of the current TSC (should be random enough)
    // FIXME: find a better way of computing the seed
#ifdef RANDOLIB_DEBUG_SEED
    rand_seed[0] = RANDOLIB_DEBUG_SEED;
#else
    bool seeded[RANDOLIB_SEED_WORDS] = {};
    // If we have the RDSEED instruction (which we check for using CPUID), use it
    if (cpu_has_rdseed()) {
        unsigned int tmp_seed;
        for (size_t i = 0; i < RANDOLIB_SEED_WORDS; i++)
            if (_rdseed32_step(&tmp_seed)) {
                rand_seed[i] = tmp_seed;
                seeded[i] = true;
            }
    }
    for (size_t i = 0; i < RANDOLIB_SEED_WORDS; i++)
        if (!seeded[i]) {
            uint64_t tsc = __rdtsc();
            rand_seed[i] = fnv_32a_buf(&tsc, sizeof(tsc), FNV1_32A_INIT);
        }
#endif

#if RANDOLIB_RNG_IS_CHACHA
    // Initialize the ChaCha RNG if we're using it
    extern RANDO_SECTION void _TRaP_chacha_init(uint32_t[8], uint32_t[2]);
    uint32_t chacha_iv[2] = { getpid(), 0x12345678 }; // FIXME: 2nd value for the IV???
    _TRaP_chacha_init(rand_seed, chacha_iv);
#endif // RANDOLIB_RNG_IS_CHACHA
}

RANDO_SECTION void API::finish() {
#if RANDOLIB_RNG_IS_CHACHA
    // Shut down the RNG
    extern RANDO_SECTION void _TRaP_chacha_finish();
    _TRaP_chacha_finish();
#endif // RANDOLIB_RNG_IS_CHACHA

    // Clear the RNG seed from memory
    API::memset(rand_seed, 0, sizeof(rand_seed));

    Buffer<char>::release_buffer(env_buf);
    env_buf = nullptr;

    FreeLibrary(ntdll);
    FreeLibrary(kernel32);

    // Save the VirtualProtect pointer before clearing everything
    __TRaP_VirtualProtect_ptr = ntdll_NtProtectVirtualMemory;

    // Clear all the global data, to prevent leaks
#if RANDOLIB_DEBUG_LEVEL_IS_ENV
    debug_level = 0;
#endif
    ntdll = nullptr;
    kernel32 = nullptr;
#define SYS_FUNCTION(library, name, API, result_type, ...)  library##_##name = nullptr;
#include "SysFunctions.inc"
#undef SYS_FUNCTION
}

// Get the PEB in an OS-independent way, directly from FS:[30h] or GS:[60h]
static RANDO_SECTION inline PEB *get_peb() {
#if RANDOLIB_IS_X86
    return (PEB*) __readfsdword(0x30);
#elif RANDOLIB_IS_X86_64
    return (PEB*) __readgsqword(0x60);
#else
#error Unknown Windows architecture
#endif
}

static RANDO_SECTION inline HANDLE get_global_heap() {
    auto *pptr = reinterpret_cast<PVOID*>(&get_peb()->Reserved4);
    return reinterpret_cast<HANDLE>(pptr[1]);
}

RANDO_SECTION void *API::mem_alloc(size_t size, bool zeroed) {
    DWORD flags = zeroed ? HEAP_ZERO_MEMORY : 0;
    return RANDO_SYS_FUNCTION(ntdll, RtlAllocateHeap, get_global_heap(), flags, size);
}

RANDO_SECTION void *API::mem_realloc(void *old_ptr, size_t new_size, bool zeroed) {
    if (old_ptr == nullptr)
        return mem_alloc(new_size, zeroed);

    DWORD flags = zeroed ? HEAP_ZERO_MEMORY : 0;
    return RANDO_SYS_FUNCTION(ntdll, RtlReAllocateHeap, get_global_heap(), flags, old_ptr, new_size);
}

RANDO_SECTION void API::mem_free(void *ptr) {
    RANDO_SYS_FUNCTION(ntdll, RtlFreeHeap, get_global_heap(), 0, ptr);
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

static inline RANDO_SECTION HANDLE GetCurrentProcess() {
    return reinterpret_cast<HANDLE>(-1);
}

RANDO_SECTION void *API::mmap(void *addr, size_t size, PagePermissions perms, bool commit) {
    SIZE_T wsize = size;
    DWORD alloc_type = commit ? (MEM_RESERVE | MEM_COMMIT) : MEM_RESERVE;
    auto win_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    RANDO_SYS_FUNCTION(ntdll, NtAllocateVirtualMemory,
                       os::GetCurrentProcess(), &addr, 0, &wsize, alloc_type, win_perms);
    return addr;
}

RANDO_SECTION void API::munmap(void *addr, size_t size, bool commit) {
    SIZE_T wsize = size;
    if (commit) {
        RANDO_SYS_FUNCTION(ntdll, NtFreeVirtualMemory,
                           os::GetCurrentProcess(), &addr, &wsize, MEM_RELEASE);
    } else {
        RANDO_SYS_FUNCTION(ntdll, NtFreeVirtualMemory,
                           os::GetCurrentProcess(), &addr, &wsize, MEM_DECOMMIT);
    }
}

RANDO_SECTION PagePermissions API::mprotect(void *addr, size_t size, PagePermissions perms) {
    SIZE_T wsize = size;
    ULONG old_win_perms = 0;
    auto win_perms = PermissionsTable[static_cast<uint8_t>(perms)];
    RANDO_SYS_FUNCTION(ntdll, NtProtectVirtualMemory,
                       os::GetCurrentProcess(), &addr, &wsize, win_perms, &old_win_perms);
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

RANDO_SECTION char *APIImpl::getenv(const char *var) {
    int buf_needed = RANDO_SYS_FUNCTION(kernel32, MultiByteToWideChar,
                                        CP_UTF8, 0, var, -1, nullptr, 0);
    Buffer<wchar_t> var_buf(buf_needed);
    RANDO_SYS_FUNCTION(kernel32, MultiByteToWideChar,
                       CP_UTF8, 0, var, -1, var_buf.data(), var_buf.capacity());

    // TODO: we can just parse the environment inside ProcessParameters ourselves,
    // which saves us an allocation
    buf_needed = RANDO_SYS_FUNCTION(kernel32, GetEnvironmentVariableW,
                                    var_buf.data(), nullptr, 0);
    if (buf_needed == 0)
        return nullptr;

    Buffer<wchar_t> res_buf(buf_needed);
    RANDO_SYS_FUNCTION(kernel32, GetEnvironmentVariableW,
                       var_buf.data(), res_buf.data(), res_buf.capacity());

    // Now convert to UTF-8
    buf_needed = RANDO_SYS_FUNCTION(kernel32, WideCharToMultiByte,
                                    CP_UTF8, 0, res_buf.data(), -1,
                                    nullptr, 0, nullptr, nullptr);
    if (env_buf == nullptr)
        env_buf = Buffer<char>::new_buffer();
    env_buf->ensure(buf_needed);
    RANDO_SYS_FUNCTION(kernel32, WideCharToMultiByte,
                       CP_UTF8, 0, res_buf.data(), -1,
                       env_buf->data(), env_buf->capacity(),
                       nullptr, nullptr);
    return env_buf->data();
}

RANDO_SECTION Pid APIImpl::getpid() {
    PROCESS_BASIC_INFORMATION pbi;
    auto res = RANDO_SYS_FUNCTION(ntdll, NtQueryInformationProcess,
                                  os::GetCurrentProcess(),
                                  ProcessBasicInformation,
                                  &pbi, sizeof(pbi), nullptr);
    return res == 0 ? pbi.UniqueProcessId : 0;
}

RANDO_SECTION File API::open_file(const char *name, bool write, bool create) {
    DWORD access = GENERIC_READ;
    DWORD sharing = FILE_SHARE_READ; // Consistent with Linux
    DWORD creation = create ? OPEN_ALWAYS : OPEN_EXISTING;
    DWORD flags = FILE_ATTRIBUTE_NORMAL;
    if (write)
        access |= GENERIC_WRITE | FILE_APPEND_DATA; // FIXME: separate flag for append???
    
    // Convert name from UTF8 to WideChar
    int buf_needed = RANDO_SYS_FUNCTION(kernel32, MultiByteToWideChar,
                                        CP_UTF8, 0, name, -1, nullptr, 0);
    Buffer<wchar_t> name_buf(buf_needed);
    RANDO_SYS_FUNCTION(kernel32, MultiByteToWideChar,
                       CP_UTF8, 0, name, -1, name_buf.data(), name_buf.capacity());

    auto res = RANDO_SYS_FUNCTION(kernel32, CreateFileW,
                                  name_buf.data(), access, sharing, nullptr,
                                  creation, flags, nullptr);
    if (res == INVALID_HANDLE_VALUE)
        return kInvalidFile;

    // If we're writing to the file, set file pointer to the end
    // FIXME: separate flag for this???
    if (write)
        RANDO_SYS_FUNCTION(kernel32, SetFilePointer, res, 0, nullptr, FILE_END);
    return res;
}

RANDO_SECTION ssize_t API::write_file(File file, const void *buf, size_t len) {
    RANDO_ASSERT(file != kInvalidFile);
    DWORD res = 0;
    // TODO: lock file while writing to it???
    RANDO_SYS_FUNCTION(kernel32, WriteFile, file, buf, len, &res, nullptr);
    return res;
}

RANDO_SECTION void API::close_file(File file) {
    RANDO_ASSERT(file != kInvalidFile);
    RANDO_SYS_FUNCTION(kernel32, CloseHandle, file);
}

#if RANDOLIB_WRITE_LAYOUTS > 0
static inline RANDO_SECTION
int build_pid_filename(char *filename, size_t len, const char *fmt, ...) {
    int res;
    va_list args;
    va_start(args, fmt);
    res = _TRaP_vsnprintf(filename, len - 1, fmt, args);
    va_end(args);
    return res;
}

RANDO_SECTION File API::open_layout_file(bool write) {
    // FIXME: does this work for paths that contain Unicode???
    // TODO: on Windows, should we use the registry to store our settings???
    const char *path = API::getenv("TEMP");
    if (path == nullptr)
        path = API::getenv("TMP");
    if (path == nullptr)
        path = API::getenv("SELFRANDO_layout_files_path");
    if (path == nullptr) {
        API::debug_printf<1>("Unknown path to layout files (perhaps set SELFRANDO_layout_files_path)!\n");
        return kInvalidFile;
    }

    // FIXME: we really, really, really need to validate/sanitize the contents of the environment variable
    auto pathlen = strlen(path);
    const int kExtraFileChars = 16; // Warning: needs to include NULL terminator
    auto filename_len = pathlen + kExtraFileChars;
    char *filename = reinterpret_cast<char*>(API::mem_alloc(filename_len, false));
    os::Pid pid = API::getpid();
    build_pid_filename(filename, filename_len, "%s\\\\%d.mlf", path, pid);
    auto res = API::open_file(filename, write, true);
    API::mem_free(filename);
    return res;
}
#endif

template<typename T>
RANDO_SECTION void Buffer<T>::clear() {
    if (m_capacity > 0) {
        API::mem_free(m_ptr);
        m_ptr = nullptr;
        m_capacity = 0;
    }
}

template<typename T>
RANDO_SECTION void Buffer<T>::ensure(size_t capacity) {
    if (capacity <= m_capacity)
        return;

    if (m_ptr != nullptr)
        API::mem_free(m_ptr);

    m_capacity = capacity;
    if (capacity > 0) {
        m_ptr = reinterpret_cast<T*>(API::mem_alloc(m_capacity * sizeof(T)));
    } else {
        m_ptr = nullptr;
    }
}

template<typename T>
RANDO_SECTION Buffer<T> *Buffer<T>::new_buffer() {
    // FIXME: this is a pretty ugly hack, but
    // we really don't want to depend on placement new here
    // WARNING: this will seriously break if Buffer<T> ever gets
    // a vtable (because of virtual functions)
    auto buffer_bytes = API::mem_alloc(sizeof(Buffer<T>), true);
    return reinterpret_cast<Buffer<T>*>(buffer_bytes);
}

template<typename T>
RANDO_SECTION void Buffer<T>::release_buffer(Buffer<T> *buf) {
    if (buf == nullptr)
        return;
    buf->~Buffer<T>();
    API::mem_free(buf);
}

RANDO_SECTION PagePermissions Module::Section::change_permissions(PagePermissions perms) const {
    if (empty())
        return PagePermissions::NONE;
    return API::mprotect(m_start.to_ptr(), m_size, perms);
}

RANDO_SECTION Module::Module(Handle info, UNICODE_STRING *name) : m_info(info), m_file_name(nullptr), m_name(name) {
    RANDO_ASSERT(info != nullptr);
    if ((info->file_header_characteristics & IMAGE_FILE_DLL) == 0) {
        // We can't trust info->module, so get the module from the OS
        m_handle = get_peb()->Reserved3[1];
    } else {
        m_handle = info->module;
    }

    m_dos_hdr = RVA2Address(0).to_ptr<IMAGE_DOS_HEADER*>();
    m_nt_hdr = RVA2Address(m_dos_hdr->e_lfanew).to_ptr<IMAGE_NT_HEADERS*>();
    m_sections = IMAGE_FIRST_SECTION(m_nt_hdr);
    for (size_t i = 0; i < m_nt_hdr->FileHeader.NumberOfSections; i++) {
        if (API::memcmp(m_sections[i].Name, kTrapSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
            m_textrap_section = &m_sections[i];
        if (API::memcmp(m_sections[i].Name, kRelocSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
            m_reloc_section = &m_sections[i];
        if (API::memcmp(m_sections[i].Name, kExportSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
            m_export_section = &m_sections[i];
    }
    arch_init();
    API::debug_printf<1>("Module@%p sections .txtrp@%p .reloc@%p .xptramp@%p\n",
                         m_handle, m_textrap_section, m_reloc_section, m_export_section);
}

RANDO_SECTION Module::~Module() {
    if (m_file_name != nullptr)
        API::mem_free(m_file_name);
}

RANDO_SECTION void Module::get_file_name() const {
    if (m_file_name != nullptr)
        return;

    Buffer<wchar_t> name_buf{ 64 };
    for (;;) {
        // We can't tell how much memory we need to store the name,
        // so try increasingly large buffers until we get a fit
        auto new_name_len = RANDO_SYS_FUNCTION(kernel32, GetModuleFileNameW,
                                               reinterpret_cast<HMODULE>(m_handle),
                                               name_buf.data(), name_buf.capacity());
        if (new_name_len < name_buf.capacity())
            break;
        name_buf.ensure(name_buf.capacity() * 2);
    }

    auto buf_needed = RANDO_SYS_FUNCTION(kernel32, WideCharToMultiByte,
                                         CP_UTF8, 0, name_buf.data(), -1,
                                         nullptr, 0, nullptr, nullptr);
    m_file_name = reinterpret_cast<char*>(API::mem_alloc(buf_needed));
    RANDO_SYS_FUNCTION(kernel32, WideCharToMultiByte,
                       CP_UTF8, 0, name_buf.data(), -1,
                       m_file_name, buf_needed,
                       nullptr, nullptr);
    API::debug_printf<1>("Module@%p:'%s'\n", m_handle, m_file_name);
}

RANDO_SECTION void Module::mark_randomized(Module::RandoState state) {
    auto old_perms = API::mprotect(m_nt_hdr, sizeof(*m_nt_hdr), PagePermissions::RW);
    // FIXME: it would be nice if we had somewhere else to put this, to avoid the copy-on-write
    // LoaderFlags works for now, because it's an obsolete flag (always set to zero)
    m_nt_hdr->OptionalHeader.LoaderFlags = API::assert_cast<DWORD>(state);
    API::mprotect(m_nt_hdr, sizeof(*m_nt_hdr), old_perms);
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
    RANDO_SYS_FUNCTION(ntdll, wcscat_s(textrap_file_name, kTmpMax, L"\\");
    RANDO_SYS_FUNCTION(ntdll, wcsncat_s(textrap_file_name, kTmpMax, module_name->Buffer, module_name->Length);
    RANDO_SYS_FUNCTION(ntdll, wcscat_s(textrap_file_name, kTmpMax, L".textrap");

    auto textrap_file = CreateFileW(textrap_file_name, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (textrap_file == INVALID_HANDLE_VALUE) {
        API::debug_printf<1>("Error opening textrap file:%d\n", GetLastError());
        return false;
    }

    *textrap_size = GetFileSize(textrap_file, NULL); // FIXME: what if textrap file > 4GB???
    *textrap_data = reinterpret_cast<BytePointer>(API::mem_alloc(*textrap_size));
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
RANDO_SECTION void Module::for_all_exec_sections(bool self_rando, ExecSectionCallback callback, void *callback_arg) {
    auto rando_state = m_nt_hdr->OptionalHeader.LoaderFlags;
    bool force_self_rando = (self_rando && rando_state == RandoState::SELF_RANDOMIZE);
    if (rando_state != RandoState::NOT_RANDOMIZED && !force_self_rando)
        return;

    if (m_reloc_section == nullptr) {
        API::debug_printf<1>("Error: module not randomized due to missing relocation information.\n");
        mark_randomized(RandoState::CANT_RANDOMIZE);
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
            API::debug_printf<1>("Error: module not randomized due to missing Trap information.\n");
            mark_randomized(RandoState::CANT_RANDOMIZE);
            return;
        }
        API::debug_printf<1>("Read %d external Trap bytes\n", textrap_size);
        release_textrap = true;
    } else if (!self_rando) {
        // Modules that have a .txtrp section must randomize themselves
        mark_randomized(RandoState::SELF_RANDOMIZE);
        return;
    } else {
        textrap_data = RVA2Address(m_textrap_section->VirtualAddress).to_ptr();
        textrap_size = m_textrap_section->Misc.VirtualSize;
    }

    // Re-map all read-only sections as writable
    PagePermissions *old_sec_perms =
        reinterpret_cast<PagePermissions*>(alloca(m_nt_hdr->FileHeader.NumberOfSections *
                                                  sizeof(PagePermissions)));
    for (size_t i = 0; i < m_nt_hdr->FileHeader.NumberOfSections; i++)
        if ((m_sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) == 0) {
            Module::Section section(*this, &m_sections[i]);
            old_sec_perms[i] = section.change_permissions(PagePermissions::RWX);
        }

    // Go through all executable sections and match them against .txtrp
    for (size_t i = 0; i < m_nt_hdr->FileHeader.NumberOfSections; i++) {
        if ((m_sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            if (API::memcmp(m_sections[i].Name, kRandoEntrySection, IMAGE_SIZEOF_SHORT_NAME) == 0)
                continue; // Skip ".rndentr"
            if (API::memcmp(m_sections[i].Name, kRandoTextSection, IMAGE_SIZEOF_SHORT_NAME) == 0) {
                __TRaP_rndtext_address = RVA2Address(m_sections[i].VirtualAddress).to_ptr<void*>();
                __TRaP_rndtext_size = m_sections[i].Misc.VirtualSize;
                continue; // Skip ".rndtext"
            }
            if (API::memcmp(m_sections[i].Name, kExportSection, IMAGE_SIZEOF_SHORT_NAME) == 0)
                continue; // Skip ".xptramp"
            // Found executable section (maybe .text)
            Module::Section exec_section(*this, &m_sections[i]);
            ::TrapInfo trap_info(textrap_data, textrap_size,
                                 TRAP_CURRENT_PLATFORM);
            auto xptramp_section = export_section();
            // FIXME: moved the page mapping from ExecSectionProcessor here
            // Still haven't decided if here is better
            (*callback)(*this, exec_section, trap_info, self_rando, callback_arg);
            // FIXME: call FlushInstructionCache???
        }
    }
    // Restore page permissions on all read-only sections
    for (size_t i = 0; i < m_nt_hdr->FileHeader.NumberOfSections; i++)
        if ((m_sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) == 0) {
            Module::Section section(*this, &m_sections[i]);
            section.change_permissions(old_sec_perms[i]);
        }
    // Un-map .txtrp from memory to prevent leaks
    if (textrap_data != nullptr)
        API::mprotect(textrap_data, textrap_size, PagePermissions::NONE);
        
    mark_randomized(RandoState::RANDOMIZED);
    if (release_textrap)
        API::mem_free(textrap_data);
}

RANDO_SECTION void Module::for_all_modules(ModuleCallback callback, void *callback_arg) {
#if 0
    PEB *peb = get_peb();
    // Reserved3[1] == ImageBaseAddress
    for (LIST_ENTRY *mod_ptr = peb->Ldr->InMemoryOrderModuleList.Flink; mod_ptr;) {
        LDR_DATA_TABLE_ENTRY *mod_entry = CONTAINING_RECORD(mod_ptr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        auto mod_base_name = reinterpret_cast<UNICODE_STRING*>(mod_entry->Reserved4);
        auto mod_full_name = mod_entry->FullDllName;
        API::debug_printf<1>("Module:%p\n", mod_entry->DllBase);
        // TODO: pass in mod_base_name to use in the external .txtrp search
        ModuleInfo mod_info = { NULL, nullptr, mod_entry->DllBase };
        Module mod(&mod_info, mod_base_name);
        (*callback)(mod, callback_arg);
        mod_ptr = mod_entry->InMemoryOrderLinks.Flink;
        if (mod_ptr == &peb->Ldr->InMemoryOrderModuleList)
            break;
    }
#endif
}

RANDO_SECTION void Module::for_all_relocations(FunctionList *functions) const {
    // Fix up the entry point
    RANDO_ASSERT(m_info->entry_loop != nullptr);
    RANDO_ASSERT(m_info->entry_loop[0] == 0xE9);

    // Patch the entry loop jump
    // FIXME: this is x86-specific
    relocate_rva(&m_info->original_entry_rva, functions, false);
    BytePointer new_entry = RVA2Address(API::assert_cast<DWORD>(m_info->original_entry_rva)).to_ptr();
    *reinterpret_cast<int32_t*>(m_info->entry_loop + 1) = API::assert_cast<int32_t>(new_entry - (m_info->entry_loop + 5));
    API::debug_printf<1>("New program entry:%p\n", new_entry);

    // Fix up relocations
    RANDO_ASSERT(m_reloc_section != nullptr);
    Section reloc_section(*this, m_reloc_section);
    auto reloc_start = reloc_section.start().to_ptr();
    auto reloc_end = reloc_section.end().to_ptr();
    for (auto block_ptr = reloc_start; block_ptr < reloc_end;) {
        auto fixup_block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(block_ptr);
        auto fixup_addr = RVA2Address(fixup_block->VirtualAddress);
        block_ptr += fixup_block->SizeOfBlock;
        // FIXME: .rndtext contains some of these relocations, so we have to map everything RWX; alternatives???
        for (auto reloc_ptr = reinterpret_cast<WORD*>(fixup_block + 1);
                  reloc_ptr < reinterpret_cast<WORD*>(block_ptr); reloc_ptr++) {
            // Handle one relocation
            // 1) get target of relocation
            auto reloc_based_type = (*reloc_ptr >> 12),
                 reloc_offset = (*reloc_ptr & 0xfff);
            auto reloc_arch_type = Relocation::type_from_based(reloc_based_type);
            if (reloc_arch_type == 0)
                continue;
            auto reloc_rva = fixup_block->VirtualAddress + reloc_offset;
            Relocation reloc(*this, RVA2Address(reloc_rva).to_ptr(), reloc_arch_type);
            functions->adjust_relocation(&reloc);
        }
    }
    fixup_target_relocations(functions);
}

}
