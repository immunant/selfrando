// SYS_FUNCTION(library, name, API, result_type, arguments...)
#ifdef SYS_FUNCTION
// ntdll functions
SYS_FUNCTION(ntdll, RtlRandomEx, WINAPI, ULONG, PULONG);
SYS_FUNCTION(ntdll, allmul, WINAPI, LONGLONG, LONGLONG, LONGLONG)
SYS_FUNCTION(ntdll, alldiv, WINAPI, LONGLONG, LONGLONG, LONGLONG)

// ntdll functions that implement the C runtime are cdecl, not WINAPI
SYS_FUNCTION(ntdll, memcmp, __cdecl, int, const void*, const void*, size_t)
SYS_FUNCTION(ntdll, memcpy, __cdecl, int, void*, const void*, size_t)
SYS_FUNCTION(ntdll, wcscat_s, __cdecl, int, wchar_t*, size_t, const wchar_t*)
SYS_FUNCTION(ntdll, wcsncat_s, __cdecl, int, wchar_t*, size_t, const wchar_t*, size_t)

// ntdll memory management functions
SYS_FUNCTION(ntdll, NtAllocateVirtualMemory, WINAPI, NTSTATUS, HANDLE, PVOID*, ULONG, SIZE_T*, ULONG, ULONG)
SYS_FUNCTION(ntdll, NtFreeVirtualMemory, WINAPI, NTSTATUS, HANDLE, PVOID*, SIZE_T*, ULONG)
SYS_FUNCTION(ntdll, NtProtectVirtualMemory, WINAPI, NTSTATUS, HANDLE, PVOID*, SIZE_T*, ULONG, PULONG)
SYS_FUNCTION(ntdll, RtlAllocateHeap, WINAPI, LPVOID, HANDLE, DWORD, SIZE_T)
SYS_FUNCTION(ntdll, RtlFreeHeap, WINAPI, BOOL, HANDLE, DWORD, LPVOID)

SYS_FUNCTION(ntdll, NtQueryInformationProcess, WINAPI, NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)

// kernel32 functions
// FIXME: not clear if we need to import these using GetProcAddress
// since every program imports kernel32.dll by default
SYS_FUNCTION(kernel32, OutputDebugStringA, WINAPI, void, LPCSTR)
SYS_FUNCTION(kernel32, QueryPerformanceFrequency, WINAPI, bool, LARGE_INTEGER*)
SYS_FUNCTION(kernel32, QueryPerformanceCounter, WINAPI, bool, LARGE_INTEGER*)
SYS_FUNCTION(kernel32, GetEnvironmentVariableA, WINAPI, DWORD, LPCSTR, LPSTR, DWORD)

// file functions
SYS_FUNCTION(kernel32, CreateFileA, WINAPI, HANDLE, LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
SYS_FUNCTION(kernel32, WriteFile, WINAPI, BOOL, HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)
SYS_FUNCTION(kernel32, CloseHandle, WINAPI, BOOL, HANDLE)
SYS_FUNCTION(kernel32, SetFilePointer, WINAPI, DWORD, HANDLE, LONG, PLONG, DWORD)

// Other functions
SYS_FUNCTION(user32, MessageBoxA, WINAPI, int, HWND, LPCSTR, LPCSTR, UINT)
#endif // SYS_FUNCTION