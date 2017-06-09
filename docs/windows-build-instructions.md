## Building Self-Randomizing Firefox on Windows

### Building the Randomizer

- Microsoft Windows Vista or later.
- [Visual Studio](http://www.visualstudio.com/downloads/download-visual-studio-vs#d-express-windows-desktop), e.g., Community Edition 2013.
- [WinDbg](http://msdn.microsoft.com/en-us/windows/hardware/hh852365) (part of the Windows SDK) to debug self-randomizing binaries.
- Git VCS for Windows. e.g.,
 - [Github for Windows](https://windows.github.com/) or
 - [Git for Windows](http://msysgit.github.io/) (can be installed from within Visual Studio)
- Add TRaP information to Visual Studio C/C++ libraries by running `self-rando-windows/Scripts/trap-msvc-libs.py`. This will copy over the following libraries from the Visual Studio distribution to the new sub-directory `TrappedMSVCLibs` and run `TrapLib.exe` on each of them to add a new section `.textrap`. The files we instrument so far include:
     - `libcmt.lib`
     - `libcmtd.lib`
     - `libcpmt.lib`
     - `libcpmt1.lib`
     - `libcptmd.lib`
     - `libcpmtd0.lib`
     - `libcpmtd1.lib`
     - `msvcrt.lib`
     - `msvcrtd.lib`
     - `msvcprt.lib`
     - `msvcprtd.lib`
- This list of libraries suffices for Firefox but may need to be expanded for other programs.
- **WARNING**: the path to `self-rando-windows` should not contain any spaces.
- Running `trap-msvc-libs.py` also generates a machine-specific script `set-buildvars-cygwin.sh` used to intercept calls to the MSVC linker to create self-randomizing binaries.

### Building 32-bit Firefox Nightly

- [Mozilla Build Prerequisites for Windows](https://ftp.mozilla.org/pub/mozilla.org/mozilla/libraries/win32/MozillaBuildSetup-Latest.exe) this includes
 - [Mercurial](http://mercurial.selenic.com/downloads) VCS to build Firefox from source
 - [Python for Windows](https://www.python.org/downloads/windows/) for the Firefox build system
- [Firefox](https://developer.mozilla.org/en-US/docs/Simple_Firefox_build) build from source
 - Checkout sources using `hg clone https://hg.mozilla.org/mozilla-release`.
 - Switch to Firefox version 34 or lower (required for now, build breaks for newer versions). Tag `FIREFOX_34_0_RELEASE` should work fine, switch using `hg update FIREFOX_34_0_RELEASE`.
 - Start a command prompt using `c:\mozilla-build\start-shell-msvc2013.bat` (for Visual Studio 2013).
 - Source `self-rando-windows/Scripts/set-buildvars-cygwin.sh` (created by `trap-msvc-libs.py`) **or**
   - Set the `MSVC_LINKER` environment variable to the full path of the MSVC linker, in quotes and with forward slashes. Example: `export MSVC_LINKER="c:/Program Files (x86)/Microsoft Visual Studio 12.0/VC/BIN/amd64_x86/link.exe"` on 64-bit Windows with Visual Studio 2013.
   - Add `self-rando-windows/Release` (or `Debug`) to the beginning of the `PATH` variable, in forward-slash Cygwin-compatible form. Example: `export PATH=/c/Users/JohnDoe/self-rando-windows/Release:$PATH`. Avoid spaces in path.
   - Add the directory with the TRaP-friendly libraries to the beginning of the `LIB` and `LIBPATH` variables. Example: `export LIB="c:\Users\JohnDoe\self-rando-windows\TrappedMSVCLibs;"$LIB`. Note the semicolon inside the double quotes.
 - copy `mozconfig.self-rando` to `mozilla-central/mozconfig`, then edit it before building (may need to change the `PATH` variable inside).
 - Build using `./mach build` in the `mozilla-central` directory.

### Testing 32-bit Firefox
- To check that a library contains TRaP information, run `dumpbin --all <filename>` and check it has a `.textrap` section.
- run `mach run` to start self-randomizing Firefox

### Building LLVM from Command Line (with Visual Studio 2013)
- Install [Cmake](http://www.cmake.org/download/)
- Install [MingW](http://gnuwin32.sourceforge.net/) and add to `PATH`
 - Install Unix command line tools by running `mingw-get install msys` with `mingw-get` on the path.
 - Add `%MINGW_HOME%\msys\1.0\bin` to the `PATH`.
- Follow [Getting Started](http://llvm.org/docs/GettingStartedVS.html) instructions for Windows.
 - Note: instructions advise use of *GnuWin32* but MingW seems to a better way to get the required Unix commands.
 - Set the `MSVC_LINKER` environment variable to the full path of the MSVC linker, **without quotes and with backslashes**. Example: `set MSVC_LINKER=c:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\BIN\amd64_x86\link.exe` on 64-bit Windows with Visual Studio 2013.
 - Add `link.exe` and `lib.exe` to MSVC tools path:
   - edit `C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\vcvars32`. Change the line `@if exist "%VCINSTALLDIR%BIN" set PATH=%VCINSTALLDIR%BIN;%PATH%` to `@if exist "%VCINSTALLDIR%BIN" set PATH=\Path\to\self-rando-windows\Debug;%VCINSTALLDIR%BIN;%PATH%`.
   - edit `C:\Program Files (x86)\MSBuild\Microsoft.Cpp\v4.0\V120\Microsoft.Cpp.Common.props`. Change

```xml
<!-- VC directories -->
<PropertyGroup>
  <VC_ExecutablePath_x86_x86>$(VCInstallDir)bin</VC_ExecutablePath_x86_x86>
  <VC_ExecutablePath_x86_x64>$(VCInstallDir)bin\x86_amd64</VC_ExecutablePath_x86_x64>
...
</PropertyGroup>
```

```xml
<!-- VC directories -->
<PropertyGroup>
  <VC_ExecutablePath_x86_x86>\Path\to\self-rando-windows\Debug;$(VCInstallDir)bin</VC_ExecutablePath_x86_x86>
  <VC_ExecutablePath_x86_x64>\Path\to\self-rando-windows\Debug;$(VCInstallDir)bin\x86_amd64</VC_ExecutablePath_x86_x64>
  ...
</PropertyGroup>
```
**WARNING** Revert `Microsoft.Cpp.Common.properties` before building within Visual Studio.

 - Make sure code is built with `/Gy` (Function-Level Linking) enabled. Add the following to `CMakeLists.txt` in the LLVM source directory before running CMake.
 ```
 if( MSVC )
 SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Gy")
 endif()
 ```
 - To enable faster builds, change `set(LLVM_TARGETS_TO_BUILD "all"...` to `set(LLVM_TARGETS_TO_BUILD "X86"`. 
 - Open a command line from the `Visual Studio Tools` folder and use `msbuild LLVM.sln` to build from the command line
