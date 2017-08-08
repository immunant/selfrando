# Preparing to build selfrando

Tested on Windows 10 build 1607 using Visual Studio 2015 Update 3. **Note:** Debug builds are broken on Visual Studio 2015, update 3. It is assumed that python 2.7 is installed to `C:\Python27`.

# Building selfrando for Win32 (x86) platforms
1. Check out or unpack selfrando to `%SR_HOME%`
2. Open a terminal (`cmd.exe`) and run:
```
msbuild %SR_HOME%\self-rando-windows.sln /p:Configuration=Release /verbosity:minimal /p:Platform=Win32
```

# Building selfrando for x64 (amd64) platforms
1. Check out or unpack selfrando to `%SR_HOME%`
2. Open a terminal (`cmd.exe`) and run:
```
msbuild %SR_HOME%\self-rando-windows.sln /p:Configuration=Release /verbosity:minimal /p:Platform=x64
```

# Applying selfrando to Win32 (x86) programs
1. Open a terminal window (`cmd.exe`, not powershell)
2. `call "%VS140COMNTOOLS%\..\..\VC\vcvarsall.bat" %VCVARS_PLATFORM%`
3. `SET PATH=C:\Python27;%PATH%`
4. `python %SR_HOME%\scripts\trap-msvc-libs.py` (This step only needs to be performed once for each platform)
5. `python %SR_HOME%\scripts\gen_scripts.py`
6. For each `.vcxproj` project file that should build with selfrando, run:
`python %SR_HOME%\scripts\update_vcxproj.py --inplace -i python.vcxproj`
(**Note:** this will rewrite the `.vcxproj` file in place, make sure to keep a backup or use the `-o` option to specify the output file.)
7. Build your C/C++ Win32 program as usual using `msbuild` or Visual Studio.

# Testing whether a Win32 program is protected by selfrando
1. Open a terminal window (`cmd.exe`, not powershell)
2. `call "%VS140COMNTOOLS%\..\..\VC\vcvarsall.bat" %VCVARS_PLATFORM%`
3. `dumpbin /section:.txtrp %PATH_TO_YOUR_EXE_OR_DLL%`

Output should be similar to
```
Microsoft (R) COFF/PE Dumper Version 14.00.24215.1
Copyright (C) Microsoft Corporation.  All rights reserved.
Dump of file C:\projects\selfrando\Release\SimpleRandoTest.exe
File Type: EXECUTABLE IMAGE
SECTION HEADER #7
  .txtrp name
     26C virtual size
    D000 virtual address (0040D000 to 0040D26B)
     400 size of raw data
    7E00 file pointer to raw data (00007E00 to 000081FF)
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
42000040 flags
         Initialized Data
         Discardable
         Read Only
  Summary
        1000 .txtrp
```

See `%SR_HOME%\tests\win32\python36.ps1` for an example on how to automatically apply selfrando to a Visual Studio project.