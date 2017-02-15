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

#include "stdafx.h"

#pragma comment(lib, "shlwapi")

static _TCHAR kLinkerPathVar[] = TEXT("MSVC_LINKER_PATH");
static _TCHAR kLinkerName[] = TEXT("\\link.exe");

# define BACKSLASH TCHAR('\\')
# define DOUBLEQUOTE TCHAR('"')
// Use algorithm from http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx
TString QuoteSpaces(const _TCHAR *arg) {
	TString input(arg), res;
	
	// Return argument as-is if possible
	if (!input.empty() && input.find_first_of(L" \t\r\n\v\"\\") == input.npos)
		return input;

	// Return argument as a quoted string
	const size_t arg_len = _tcslen(arg);
	res.push_back(DOUBLEQUOTE);
	for (size_t i = 0; i < arg_len; i++) {
		unsigned noBackslashes = 0;

		while (i < arg_len && arg[i] == BACKSLASH) {
			i++;
			noBackslashes++;
		}

		if (i == arg_len) {
			// Escape all backslashes but don't escape the
			// terminating double quotation we add after the loop
			res.append(noBackslashes * 2, BACKSLASH);
			break;
		} else if (arg[i] == DOUBLEQUOTE) {
			// Escape all backslashes and the double quote
			res.append(noBackslashes * 2 + 1, BACKSLASH);
			res.push_back(DOUBLEQUOTE);
		} else {
			// No need to escape backslashes here
			res.append(noBackslashes, BACKSLASH);
			res.push_back(arg[i]);
		}
	}

	res.push_back(DOUBLEQUOTE);
	return res;
}

TString LocateRandoFile(const _TCHAR *file, bool quote) {
    _TCHAR *wrapper_path;
    _get_tpgmptr(&wrapper_path);

    _TCHAR *file_dir = _tcsdup(wrapper_path);
    PathRemoveFileSpec(file_dir);
    PathAddBackslash(file_dir); // Should be enough room left over for this

    // FIXME: this copies the string two times in total (triple with QuoteSpaces); remove one copy???
    TString file_path(file_dir);
    file_path.append(file);
    free(file_dir);
    return quote ? QuoteSpaces(file_path.data()) : file_path;
}

TString LocateMSVCLinker() {
    TString linker_path;
    auto linker_path_len = GetEnvironmentVariable(kLinkerPathVar, NULL, 0);
    assert(linker_path_len > 0 && "MSVC_LINKER_PATH variable not set");
    linker_path.resize(linker_path_len, 'X');
    GetEnvironmentVariable(kLinkerPathVar, const_cast<_TCHAR*>(linker_path.data()), linker_path_len + 1);

    std::basic_istringstream<TCHAR> iss(linker_path);
    TString path;
    while (std::getline(iss, path, _T(';'))) {
        path.append(kLinkerName);
        if (PathFileExists(path.c_str()))
            return path;
    }
    return TString();
}

// helper method to print out args passed to link.exe
void PrintArgs(const std::vector<const _TCHAR*>& args) {
	TString str;
	for (auto &arg : args) {
		if (arg == NULL)
			break;
		str.append(arg);
		str.append(TEXT("\r\n"));
	}

	fwprintf(stderr, L"PrintArgs: %s\n", str.c_str());
}
