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
#include "CppUnitTest.h"

// For CommandLineToArgvW
#pragma comment(lib, "Shell32")

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace WrapperCommonTests
{
	TEST_CLASS(QuoteSpacesUnitTest)
	{
	public:
		
		TEST_METHOD(TestNoSpace)
		{
			const _TCHAR *input = TEXT("nospaceshere");
			// When string contains no spaces, the output is the same string
			TString expected = TString(input);
			TString actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);
		}

		TEST_METHOD(TestSpace)
		{
			const _TCHAR *input = TEXT("space here");
			// When string contains spaces, output is quoted
			TString expected = TString(TEXT("\"space here\""));
			TString actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);

			// Strings with tabs get quoted too
			input = TEXT("tab\there");
			expected = TString(TEXT("\"tab\there\""));
			actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);

			// Strings with newlines get quoted too
			input = TEXT("linefeed\nhere");
			expected = TString(TEXT("\"linefeed\nhere\""));
			actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);

			input = TEXT("carriagereturn\rhere");
			expected = TString(TEXT("\"carriagereturn\rhere\""));
			actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);
		}

		TEST_METHOD(TestQuotes)
		{
			const _TCHAR *input = TEXT("quotes\"work\"");
			
			// Double quotes in strings are escaped and the output is quoted
			TString expected = TString(TEXT("\"quotes\\\"work\\\"\""));
			TString actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);

			// Same test adding spaces
			input = TEXT("quotes\"and space\"");
			expected = TString(TEXT("\"quotes\\\"and space\\\"\""));
			actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);
		}

		TEST_METHOD(TestBackslashes)
		{
			const _TCHAR *input = TEXT("\\");

			// Strings containing backslashes are quoted and backslashes are escaped
			TString expected = TString(TEXT("\"\\\\\""));
			TString actual = QuoteSpaces(input);
			Assert::AreEqual(expected, actual);
		}

		// Helper method
		const unsigned GetNumParsedArgs(std::vector<const _TCHAR *>& args) 
		{
			// Join vector of strings with spaces
			TString res;
			for (auto it = args.begin(); it != args.end(); it++)
			{
				res.append(QuoteSpaces(*it));
				res.push_back(TCHAR(' '));
			}

			// Convert TString to LPWSTR* using safe string copy
			wchar_t argBuffer[2048];
			HRESULT hr = ::StringCchCopy(argBuffer, _countof(argBuffer), res.c_str());
			assert(hr != STRSAFE_E_INSUFFICIENT_BUFFER);
			assert(hr == S_OK);

			// Parse the argument string (allocates memory for result)
			int numArgs = 0;
			LPWSTR *argList = CommandLineToArgvW(argBuffer, &numArgs);
			
			// Free memory allocated for CommandLineToArgvW arguments.
			LocalFree(argList);

			return numArgs;
		}

		TEST_METHOD(TestNumArgs)
		{
			// Easy case
			std::vector<const _TCHAR *> args;
			args.push_back(TEXT("child.exe"));
			args.push_back(TEXT("argument 1"));
			args.push_back(TEXT("argument 2"));
			Assert::AreEqual(3U, GetNumParsedArgs(args));

			// Quotes and spaces
			args.clear();
			args.push_back(TEXT("child.exe"));
			args.push_back(TEXT("arg \"with\" quotes"));
			args.push_back(TEXT("argument\" 2\""));
			Assert::AreEqual(3U, GetNumParsedArgs(args));

			// Backslashes and spaces
			args.clear();
			args.push_back(TEXT("\n\rchild.exe"));
			args.push_back(TEXT("c:\\path with\\spaces in\\it\t"));
			Assert::AreEqual(2U, GetNumParsedArgs(args));

			// Backslashes, quotes and spaces
			args.clear();
			args.push_back(TEXT("\\"));
			args.push_back(TEXT("\\\""));
			args.push_back(TEXT("\\ \""));
			args.push_back(TEXT("\" \\"));
			Assert::AreEqual(4U, GetNumParsedArgs(args));
		}
	};
}
