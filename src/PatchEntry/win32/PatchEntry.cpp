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

// PatchEntry.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

static const char kEntrySection[] = ".rndentr";
static const char kTrampSection[] = ".xptramp";

#pragma pack(1)
struct ExportTrampoline {
    BYTE jump_insn;
    DWORD offset;
};

static const int kPush0Offset = 13;

int _tmain(int argc, _TCHAR* argv[])
{
    // FIXME: output into a separate file???
    if (argc < 2) {
        printf("Usage: PatchEntry <binary>\n");
        return 1;
    }

    HANDLE file_handle = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("Couldn't open input file, error %d\n"), GetLastError());
        return 1;
    }

    HANDLE file_map = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (file_map == NULL) {
        _tprintf(TEXT("Couldn't create mapping of input file, error %d\n"), GetLastError());
        CloseHandle(file_handle);
        return 2;
    }

    void *file_view = MapViewOfFile(file_map, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (file_view == NULL) {
        _tprintf(TEXT("Couldn't map view of input file, error %d\n"), GetLastError());
        CloseHandle(file_map);
        CloseHandle(file_handle);
        return 3;
    }

    auto file_to_mem_ptr = [file_view](DWORD file_ptr) {
        return reinterpret_cast<BYTE*>(file_view) + file_ptr;
    };

    IMAGE_DOS_HEADER *dos_hdr = reinterpret_cast<IMAGE_DOS_HEADER*>(file_view);
    assert(dos_hdr->e_magic == IMAGE_DOS_SIGNATURE && "Input file not a DOS executable");

    // FIXME: 32-bit only for now
    auto nt_hdr = reinterpret_cast<IMAGE_NT_HEADERS*>(file_to_mem_ptr(dos_hdr->e_lfanew));
    assert(nt_hdr->Signature == IMAGE_NT_SIGNATURE && "Bad header signature");
    assert(nt_hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && "Bad optional header signature");
    assert(nt_hdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && "Wrong binary architecture");

    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt_hdr);
    auto find_section_name = [nt_hdr, sections](const char *name) {
        for (size_t i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++)
            if (memcmp(sections[i].Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
                return &sections[i];
        return static_cast<IMAGE_SECTION_HEADER*>(nullptr);
    };
    auto find_section_rva = [nt_hdr, sections](DWORD rva) {
        // TODO: make it sub-linear in running time
        for (size_t i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++)
            if (rva >= sections[i].VirtualAddress &&
                rva < (sections[i].VirtualAddress + sections[i].Misc.VirtualSize))
                return &sections[i];
        return static_cast<IMAGE_SECTION_HEADER*>(nullptr);
    };
    auto rva_to_ptr = [&find_section_rva, &file_to_mem_ptr](DWORD rva) {
        auto rva_sec = find_section_rva(rva);
        assert(rva_sec != nullptr && "Export table not found in any section");
        auto rva_file_ptr = rva_sec->PointerToRawData + (rva - rva_sec->VirtualAddress);
        return file_to_mem_ptr(rva_file_ptr);
    };

    // Patch entry point to point to start of .rndentr
    auto entry_sec = find_section_name(kEntrySection);
    if (entry_sec != nullptr) {
        assert((entry_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && ".rndentr section not executable");
        DWORD *sec_ptr = reinterpret_cast<DWORD*>(file_to_mem_ptr(entry_sec->PointerToRawData));
        if (*sec_ptr == 0) {
            *sec_ptr = nt_hdr->OptionalHeader.AddressOfEntryPoint;
            // Set the new entry point to just after where we store the old one
            nt_hdr->OptionalHeader.AddressOfEntryPoint = entry_sec->VirtualAddress + sizeof(*sec_ptr);
            if ((nt_hdr->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
                // If the binary is not a DLL, patch the "PUSH hInstance" away
                BYTE *code_ptr = reinterpret_cast<BYTE*>(sec_ptr + 1);
                assert(code_ptr[kPush0Offset + 0] == 0xFF && "Expected PUSH opcode");
                assert(code_ptr[kPush0Offset + 1] == 0x74 && "Expected MRM==0x74");
                assert(code_ptr[kPush0Offset + 2] == 0x24 && "Expected SIB==0x24");
                assert(code_ptr[kPush0Offset + 3] == 0x14 && "Expected offset 20");
                code_ptr[kPush0Offset + 0] = 0x6A; // PUSH 0 (together with next byte)
                code_ptr[kPush0Offset + 1] = 0x00;
                code_ptr[kPush0Offset + 2] = 0x66;
                code_ptr[kPush0Offset + 3] = 0x90;
            }
        }
    }
    // Patch export table to point to .xptramp trampolines
    auto &export_hdr_dir = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_hdr_dir.Size > 0) {
        auto xptramp_sec = find_section_name(kTrampSection);
        assert(xptramp_sec != nullptr && "DLL file doesn't contain .xptramp");
        auto tramp_start = file_to_mem_ptr(xptramp_sec->PointerToRawData);
        auto tramp_end = tramp_start + xptramp_sec->SizeOfRawData;
        auto tramp_rva = [xptramp_sec, tramp_start](ExportTrampoline *tr) {
            return (reinterpret_cast<BYTE*>(tr) - tramp_start) + xptramp_sec->VirtualAddress;
        };
        std::unordered_map<DWORD, ExportTrampoline*> trampoline_map;
        for (ExportTrampoline *tr = reinterpret_cast<ExportTrampoline*>(tramp_start);
                               tr < reinterpret_cast<ExportTrampoline*>(tramp_end); tr++)
            if (tr->jump_insn == 0xE9) {
                auto jump_target_rva = tramp_rva(tr) + sizeof(ExportTrampoline) + tr->offset;
                trampoline_map[jump_target_rva] = tr;
            }

        assert(export_hdr_dir.VirtualAddress > 0 && "Invalid export table address");
        auto export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(rva_to_ptr(export_hdr_dir.VirtualAddress));
        assert(export_dir != nullptr && "Can't find section containing export table");
        auto num_exports = export_dir->NumberOfFunctions;
        auto export_table = reinterpret_cast<DWORD*>(rva_to_ptr(export_dir->AddressOfFunctions));
        for (size_t i = 0; i < num_exports; i++) {
            auto export_addr = export_table[i];
            auto export_sec = find_section_rva(export_addr);
            assert(export_sec != nullptr && "Exported symbol in unknown section");
            if ((export_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
                // Heuristics: only use trampolines for symbols inside code section
                auto tramp = trampoline_map[export_addr];
                assert(tramp != nullptr && "No trampoline entry found for exported symbol");
                export_table[i] = tramp_rva(tramp);
            }
        }
    }
    // FIXME: correct checksum in optional header

    UnmapViewOfFile(file_view);
    CloseHandle(file_map);
    CloseHandle(file_handle);
	return 0;
}

