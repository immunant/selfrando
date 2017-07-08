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

// link-wrapper.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#pragma comment(lib, "shlwapi")

static _TCHAR kRandoLib[] = TEXT("RandoLib.lib");
static _TCHAR kLibOption[] = TEXT("lib");
static _TCHAR kOutOption[] = TEXT("out:");

static _TCHAR kLinkerExtraArg1[] = TEXT("/INCLUDE:__TRaP_RandoEntry");
static _TCHAR kLinkerExtraArg2[] = TEXT("/INCLUDE:__TRaP_Header");
static _TCHAR kLinkerNoIncrementalArg[] = TEXT("/INCREMENTAL:NO");

static TString ProcessArg(const _TCHAR *arg);
static TString ProcessCommands(const _TCHAR *file);
static TString ProcessInputFile(const _TCHAR *file);

bool lib_mode = false;
TString first_object_name;
TString out_argument;

static TString ProcessArg(const _TCHAR *arg) {
    if (arg[0] == _T('@')) {
        TString res{ arg[0] };
        res += ProcessCommands(arg + 1);
        return res;
    } else if (arg[0] == _T('/') || arg[0] == _T('-')) {
        const _TCHAR *opt = arg + 1;
        if (_tcsicmp(opt, kLibOption) == 0) {
            lib_mode = true;
        } else if (_tcsnicmp(opt, kOutOption, _tcslen(kOutOption)) == 0) {
            out_argument.assign(opt + _tcslen(kOutOption));
        }
        return TString(arg);
    } else {
        // Input file, process
       return ProcessInputFile(arg);
    }
}

static TString ProcessCommands(const _TCHAR *file) {
	FILE *fin;
#ifdef UNICODE
    int err = _wfopen_s(&fin, file, L"r,ccs=unicode");
#else
    int err = fopen_s(&fin, file, "r");
#endif
    if (err)
        return TString(file);

    FILE *fout;
    auto output_file = TempFile::Create(TEXT(".txt"), true);
#ifdef UNICODE
    err = _wfopen_s(&fout, output_file.data(), L"w,ccs=unicode");
#else
    err = fopen_s(&fout, output_file.data(), "w");
#endif
    if (err) {
        perror("LinkWrapper:ProcessCommands");
        exit(err);
    }

    _TINT ch = _gettc(fin);
	while (ch != _TEOF) {
        while (ch != _TEOF && _istspace(ch)) {
            _puttc(ch, fout);
            ch = _gettc(fin);
        }

        // FIXME: input files with spaces in them??? (are they quoted???)
		TString word;
		while (ch != _TEOF && !_istspace(ch)) {
			word.push_back(ch);
			ch = _gettc(fin);
		}
        // FIXME: handle comments (starting with ';')
        auto comment_pos = word.find(TCHAR(';'));
        assert(comment_pos == -1 && "Found comment in command file");
		if (!word.empty()) {
			auto new_word = ProcessArg(word.data());
            _fputts(new_word.data(), fout);
		}
	}
	fclose(fin);
    fclose(fout);
    return output_file;
}

static TString ProcessInputFile(const _TCHAR *file) {
    // If the file name is surrounded by quotes, remove them
    auto input_file = StripQuotes(TString(file));

	// If the file ends something other than .obj, skip it
    auto dot = PathFindExtension(input_file.c_str());
	if (dot == nullptr) {
		// MSDN says that files without an extension get .obj appended
		input_file.append(TEXT(".obj"));
	} else if (_tcsicmp(dot, TEXT(".lib")) == 0) {
        auto tmp_file = TempFile::Create(TEXT(".lib"), true);
        auto trap_status = TRaPCOFFLibrary(input_file.c_str(), tmp_file.data());
#if 0
        if (trap_status == TRaPStatus::TRAP_ERROR) {
            perror("LinkWrapper:ProcessInputFile:TRaPCOFFLibrary");
            exit(-1);
        }
#endif
        if (trap_status == TRaPStatus::TRAP_ADDED)
            return tmp_file;
        return input_file;
    } else if (_tcsicmp(dot, TEXT(".obj")) != 0 &&
               _tcsicmp(dot, TEXT(".o")) != 0) // FIXME: create a list of allowed object file extensions (or let TRaPCOFFObject detect object files itself)
		return input_file;

	// Run TrapObj.exe <file.obj> <file.obj>
	// TODO: parallelize this (using WaitForMultipleObjects)
    // FIXME: output to a temporary file instead, and erase it afterwards
    // FIXME: Trap.cpp leaks some memory
    TString output_file = input_file;
    COFFObject coff_file;
    if (!coff_file.readFromFile(input_file.c_str()))
        return output_file;
    if (coff_file.createTRaPInfo()) {
        output_file = TempFile::Create(TEXT(".obj"), true);
        coff_file.writeToFile(output_file.c_str());
    }

    // Mark this input file if it's the first
    if (first_object_name.empty())
        first_object_name = input_file;
    return output_file;
}

static TString EmitExports(const std::vector<TString> &escaped_args) {
    auto uuid_lib_file = TempFile::Create(TEXT(".lib"), true);
    auto uuid_exp_file = uuid_lib_file;
    uuid_exp_file.replace(uuid_exp_file.length() - 4, 4, TEXT(".exp"));
    TempFile::AutoDeleteFile(uuid_exp_file);

    // Call link.exe -lib -def <rest of linker arguments> -out:<uuid_lib_file>
    auto linker_exe = LocateMSVCLinker();
    auto linker_exe_esc = QuoteSpaces(linker_exe.data());
    std::vector<const _TCHAR*> export_args;
    export_args.push_back(linker_exe_esc.data());
    export_args.push_back(TEXT("-lib"));
    export_args.push_back(TEXT("-def")); // If the original includes "/DEF" or "-DEF", it should override this one
    // FIXME: this passes many link.exe args to lib.exe which generates warnings
    for (auto &escaped_arg : escaped_args)
        export_args.push_back(escaped_arg.data());
    TString out_arg(TEXT("-out:"));
    out_arg += uuid_lib_file;
    export_args.push_back(out_arg.data());
    export_args.push_back(NULL);
	//PrintArgs(export_args);
	auto errnum = _tspawnvp(_P_WAIT, linker_exe.data(), export_args.data());
	if (errnum) {
		perror("LinkWrapper:EmitExports");
		exit(errnum);
	}

    // Convert the exports file to the trampoline object file
    auto exports_obj_file = TempFile::Create(TEXT(".obj"), true);
    bool converted = ConvertExports(uuid_exp_file.data(), exports_obj_file.data());
    return converted ? exports_obj_file : TString();
}

template<size_t N>
static inline bool StripSuffix(TString &str, const _TCHAR (&suffix)[N]) {
    if (N >= str.length())
        return false;

    auto str_suffix = str.substr(str.length() - N + 1, N - 1).c_str();
    if (_tcsicmp(str_suffix, suffix) == 0) {
        str = str.substr(0, str.length() - N + 1);
        return true;
    }
    return false;
}

static TString FindOutputFile() {
    TString candidate;
    if (!out_argument.empty()) {
        candidate = StripQuotes(out_argument);
    } else if (!first_object_name.empty()) {
        candidate = first_object_name;
        if (!StripSuffix(candidate, TEXT(".obj")))
            StripSuffix(candidate, TEXT(".o"));
    } else {
        return TString();
    }
    if (PathFileExists(candidate.c_str()))
        return candidate;

    // FIXME: we should figure out from the linker's command line
    // whether the output file is an .exe or .dll
    TString exe_file = candidate + TEXT(".exe");
    if (PathFileExists(exe_file.c_str()))
        return exe_file;

    TString dll_file = candidate + TEXT(".dll");
    if (PathFileExists(dll_file.c_str()))
        return dll_file;

    return TString();
}

static void CallPatchEntry() {
    auto output_file = FindOutputFile();
    if (!output_file.empty()) {
        // FIXME: requires PatchEntry.exe in path
        auto errnum = _tspawnlp(_P_WAIT, TEXT("PatchEntry"),
                               TEXT("PatchEntry"), output_file.c_str(), NULL);
        if (errnum) {
            perror("LinkWrapper:PatchEntry");
            fprintf(stderr, "PatchEntry return value:%d\n", errnum);
            exit(errnum);
        }
    }
}

int _tmain(int argc, _TCHAR* argv[])
{
    // FIXME: MSDN says that the linker also parses arguments from the LINK environment variable
    std::vector<const _TCHAR*> linker_args;
    std::vector<TString> escaped_args;
    auto linker_exe = LocateMSVCLinker();
    auto linker_exe_esc = QuoteSpaces(linker_exe.data());
    linker_args.push_back(linker_exe_esc.data()); // Needed by _tspawnvp
    for (int i = 1; i < argc; i++) {
        auto trap_file = ProcessArg(argv[i]);
        escaped_args.push_back(QuoteSpaces(trap_file.data()));
    }
    for (auto &escaped_arg : escaped_args)
        linker_args.push_back(escaped_arg.data());

    // Make a new linker arguments containing the following:
    // 1) The linker program name as argv[0] (required by _texecvp)
    // 2) The original arguments passed to the linker
    // 3) All additional arguments we add in (such as the path to RandoLib.lib)
    // 4) Terminating NULL pointer
    // When producing an executable/DLL, add in RandoLib.lib
    TString rando_lib_path, exports_file;
    if (!lib_mode) {
        exports_file = EmitExports(escaped_args);
        linker_args.push_back(exports_file.data());
        linker_args.push_back(kLinkerExtraArg1);
        linker_args.push_back(kLinkerExtraArg2);
        linker_args.push_back(kRandoLib);
        // We need to disable incremental linking because it breaks our stuff
        // (for some reason, the linker adds an extra 0 byte to the end of each .txtrp entry)
        linker_args.push_back(kLinkerNoIncrementalArg);
    }
    linker_args.push_back(NULL);
	//PrintArgs(linker_args);
    auto errnum = _tspawnvp(_P_WAIT, linker_exe.data(), linker_args.data());
	if (errnum) {
		perror("LinkWrapper:_tmain");
		exit(errnum);
	}
    if (!lib_mode)
        CallPatchEntry();

	return errnum;
}
