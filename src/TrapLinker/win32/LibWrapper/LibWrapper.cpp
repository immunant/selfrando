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

// LibWrapper.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

static _TCHAR kLinkWrapperExe[] = TEXT("link.exe");
static _TCHAR kLibModeDashArg[] = TEXT("-lib");

int _tmain(int argc, _TCHAR* argv[])
{
    // Just run: LinkWrapper.exe -lib <rest of arguments>
    std::vector<const _TCHAR*> linker_args;
    std::vector<TString> escaped_args;
    auto link_wrapper_exe = LocateRandoFile(kLinkWrapperExe, false);
    linker_args.push_back(link_wrapper_exe.data()); // Needed by _texecvp
    linker_args.push_back(kLibModeDashArg);
    for (int i = 1; i < argc; i++) {
        escaped_args.push_back(QuoteSpaces(argv[i]));
    }
    for (auto &escaped_arg : escaped_args)
        linker_args.push_back(escaped_arg.data());
    linker_args.push_back(NULL);
	auto errnum = _tspawnvp(_P_WAIT, linker_args[0], linker_args.data());
	if (errnum) {
		perror("LibWrapper:_tmain");
		exit(errnum);
	}
	return errnum;
}
