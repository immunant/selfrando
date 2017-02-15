;
; Copyright (c) 2014-2015, The Regents of the University of California
; Copyright (c) 2017 Immunant Inc.
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
extern __TRaP_RandoMain:near

rndentry segment byte read execute alias(".rndentr")
; This stores the original contents of AddressOfEntryPoint from the PE optional header
; We store it in a separate section to make it easier to patch on-disk, and also to un-map from memory
__TRaP_OriginalEntry dd 0

; New program entry point, that AddressOfEntryPoint will point to
__TRaP_RandoEntry proc
entry_loop:
    db 0E9h
    dd 0

do_rando:
	; WARNING: PatchEntry expects this to be at a fixed offset
	; PatchEntry changes this to "PUSH 0 ; NOP" if we're not in a DLL
	push rcx
	lea rax, entry_loop
	push rax
    mov eax, dword ptr [__TRaP_OriginalEntry]
    push rax
	; Push pointer to ModuleInfo structure as single parameter
    mov rcx, rsp
    sub rsp, 32
	call __TRaP_RandoMain
    add rsp, 32

    jmp entry_loop
__TRaP_RandoEntry endp
rndentry ends

end
