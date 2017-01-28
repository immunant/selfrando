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
#pragma comment(lib, "rpcrt4")

static _TCHAR kRandoLib[] = TEXT("RandoLib.lib");
static _TCHAR kLibOption[] = TEXT("lib");

static _TCHAR kLinkerExtraArg1[] = TEXT("/INCLUDE:__TRaP_RandoEntry");
static _TCHAR kLinkerExtraArg2[] = TEXT("/INCLUDE:__TRaP_Header");
static _TCHAR kLinkerNoIncrementalArg[] = TEXT("/INCREMENTAL:NO");

static void ProcessArg(const _TCHAR *arg);
static void ProcessCommands(const _TCHAR *file);
static void ProcessInputFile(const _TCHAR *file);

bool lib_mode = false;

static void ProcessArg(const _TCHAR *arg) {
    if (arg[0] == '@') {
        ProcessCommands(arg + 1);
    } else if (arg[0] == '/' || arg[0] == '-') {
        const _TCHAR *opt = arg + 1;
        if (_tcsicmp(opt, kLibOption) == 0) {
            lib_mode = true;
            return;
        }
    } else {
        // Input file, process
        ProcessInputFile(arg);
    }
}

static void ProcessCommands(const _TCHAR *file) {
	FILE *f;
	int err = _tfopen_s(&f, file, TEXT("r"));
	if (err)
		return;

	_TINT ch = _gettc(f);
	while (ch != _TEOF) {
		while (ch != _TEOF && _istspace(ch))
			ch = _gettc(f);

        // FIXME: input files with spaces in them??? (are they quoted???)
		TString word;
		while (ch != _TEOF && !_istspace(ch)) {
			word.push_back(ch);
			ch = _gettc(f);
		}
        // FIXME: handle comments (starting with ';')
        auto comment_pos = word.find(TCHAR(';'));
        assert(comment_pos == -1 && "Found comment in command file");
		if (!word.empty()) {
			ProcessArg(word.data());
		}
	}
	fclose(f);
}

static void ProcessInputFile(const _TCHAR *file) {
	// If the file ends something other than .obj, skip it
	TString tmp;
    auto dot = PathFindExtension(file);
	if (dot == nullptr) {
		// MSDN says that files without an extension get .obj appended
		tmp.append(file);
		tmp.append(TEXT(".obj"));
		file = tmp.data();
	} else if (_tcsicmp(dot, TEXT(".lib")) == 0) {
        TRaPCOFFLibrary(file, file);
        return;
    } else if (_tcsicmp(dot, TEXT(".obj")) != 0 &&
             _tcsicmp(dot, TEXT(".o")) != 0) // FIXME: create a list of allowed object file extensions (or let TRaPCOFFFile detect object files itself)
		return;

	// Run TrapObj.exe <file.obj> <file.obj>
	// TODO: parallelize this (using WaitForMultipleObjects)
    // FIXME: output to a temporary file instead, and erase it afterwards
    // FIXME: Trap.cpp leaks some memory
    TRaPCOFFFile(file, file);
}

static TString EmitExports(const std::vector<TString> &escaped_args) {
    // FIXME: this outputs the temporaries in the current directory (for now)
    // Ideally, it would instead use $TMP as the location; however, this doesn't
    // work currently if $TMP contains spaces (which it usually does)
#if 0
    _TCHAR tmp;
    auto temp_path_len = GetTempPath(1, &tmp);
    TString temp_path(temp_path_len, TCHAR('X'));
    GetTempPath(temp_path_len, const_cast<_TCHAR*>(temp_path.data()));
#endif

    UUID uuid;
    _TINT *uuid_str; // RPC_WSTR is unsigned short*, so equivalent to _TINT*
    UuidCreate(&uuid);
    UuidToString(&uuid, &uuid_str);
    TString uuid_lib_file(reinterpret_cast<_TCHAR*>(uuid_str));
    TString uuid_exp_file = uuid_lib_file;
    TString uuid_exports_obj_file = uuid_lib_file;
    uuid_lib_file += TEXT(".lib");
    uuid_exp_file += TEXT(".exp");
    uuid_exports_obj_file += TEXT("_exports.obj");
    RpcStringFree(&uuid_str);

    // Call link.exe -lib -def <rest of linker arguments> -out:<uuid_lib_file>
    auto linker_exe = LocateMSVCLinker();
    auto linker_exe_esc = QuoteSpaces(linker_exe.data());
    std::vector<const _TCHAR*> export_args;
    export_args.push_back(linker_exe_esc.data());
    export_args.push_back(TEXT("-lib"));
    export_args.push_back(TEXT("-def")); // If the original includes "/DEF" or "-DEF", it should override this one
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
    bool converted = ConvertExports(uuid_exp_file.data(), uuid_exports_obj_file.data());
    // Delete the .lib and .exp temporaries
    DeleteFile(uuid_lib_file.data());
    DeleteFile(uuid_exp_file.data());
    return converted ? uuid_exports_obj_file : TString();
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
        ProcessArg(argv[i]);
        escaped_args.push_back(QuoteSpaces(argv[i]));
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
        rando_lib_path = LocateRandoFile(kRandoLib, true);
        exports_file = EmitExports(escaped_args);
        linker_args.push_back(exports_file.data());
        linker_args.push_back(kLinkerExtraArg1);
        linker_args.push_back(kLinkerExtraArg2);
        linker_args.push_back(const_cast<_TCHAR*>(rando_lib_path.data()));
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

    if (!exports_file.empty())
       DeleteFile(exports_file.data());
	return errnum;
}
