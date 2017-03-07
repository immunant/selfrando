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


#pragma once

#include <Windows.h>
#include <string>

typedef std::basic_string<_TCHAR> TString;

class TempFile {
public:
    static TString Create(const _TCHAR *extension, bool auto_delete);

    static void AutoDeleteFile(const TString &file) {
        GetInstance()->m_temp_files.push_back(file);
    }

private:
    // We want a singleton here whose destructor gets automatically called
    // on program exit, so it deletes all registered auto-delete files
    TempFile() {}
    
    ~TempFile() {
        for (auto &temp_file : m_temp_files)
            DeleteFile(temp_file.c_str());
    }

    static TempFile *GetInstance();

private:
    std::vector<TString> m_temp_files;
};

extern TString QuoteSpaces(const _TCHAR *arg);
extern TString StripQuotes(const TString &str);
extern TString LocateRandoFile(const _TCHAR *file, bool quote);
extern TString LocateMSVCLinker(); 
extern void PrintArgs(const std::vector<const _TCHAR*>& args);
