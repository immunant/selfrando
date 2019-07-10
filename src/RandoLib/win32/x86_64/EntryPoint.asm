;
; Copyright (c) 2014-2015, The Regents of the University of California
; Copyright (c) 2014-2019 RunSafe Security, Inc.
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
; * Redistributions of source code must retain the above copyright notice, this
;   list of conditions and the following disclaimer.
;
; * Redistributions in binary form must reproduce the above copyright notice,
;   this list of conditions and the following disclaimer in the documentation
;   and/or other materials provided with the distribution.
;
; * Neither the name of the University of California nor the names of its
;   contributors may be used to endorse or promote products derived from
;   this software without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;

public __TRaP_RandoEntry
extern _TRaP_RandoMain:near

extern __TRaP_VirtualProtect_ptr:near
extern __TRaP_rndtext_address:near
extern __TRaP_rndtext_size:near

; Trampoline to NtProtectVirtualMemory
; We put this into .rndtext so it disappears after the call
rndtext segment byte read execute alias(".rndtext") 'CODE'
virtual_protect_trampoline:
    jmp qword ptr [__TRaP_VirtualProtect_ptr]
rndtext ends

rndentry segment byte read execute alias(".rndentr") 'CODE'
; This stores the original contents of AddressOfEntryPoint from the PE optional header
; We store it in a separate section to make it easier to patch on-disk, and also to un-map from memory
__TRaP_OriginalEntry dd 0
__TRaP_FileHeaderCharacteristics dd 0

; New program entry point, that AddressOfEntryPoint will point to
__TRaP_RandoEntry proc
entry_loop:
    db 0E9h
    dd 0

do_rando:
    push r11
    push r10
    push r9
    push r8
    push rdx
	push rcx
    mov eax, dword ptr [__TRaP_FileHeaderCharacteristics]
    push rax
	lea rax, entry_loop
	push rax
    mov eax, dword ptr [__TRaP_OriginalEntry]
    push rax
	; Push pointer to ModuleInfo structure as single parameter
    mov rcx, rsp
    ; We need to reserve at least 32 bytes on the stack for the parameters
    sub rsp, 32
	call _TRaP_RandoMain
    add rsp, 32+24

    ; Remove .rndtext from memory using NtProtectVirtualMemory
    ; ProcessHandle == -1
    or rcx, -1
    ; BaseAddress == &__TRaP_rndtext_address
    lea rdx, qword ptr [__TRaP_rndtext_address]
    ; NumberOfBytesToProtect == &__TRaP_rndtext_size
    lea r8, qword ptr [__TRaP_rndtext_size]
    ; NewAccessProtection == PAGE_NOACCESS
    mov r9, 1
    ; OldAccessProtection == &temporary stack variable
    push 0
    push rsp
    sub rsp, 32
    call virtual_protect_trampoline
    add rsp, 48

    ; Clear out the VirtualProtect and .rndtext pointers
    xor rax, rax
    mov qword ptr [__TRaP_VirtualProtect_ptr], rax
    mov qword ptr [__TRaP_rndtext_address], rax
    mov qword ptr [__TRaP_rndtext_size], rax

    pop rcx
    pop rdx
    pop r8
    pop r9
    pop r10
    pop r11

    jmp entry_loop
__TRaP_RandoEntry endp
rndentry ends

end
