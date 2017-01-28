#!/bin/sh
#
# Copyright (c) 2014-2015, The Regents of the University of California
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the University of California nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# The beginning of this script is both valid shell and valid python,
# such that the script starts with the shell and is reexecuted with
# the right python.
'''which' python2.7 > /dev/null && exec python2.7 "$0" "$@" || exec python "$0" "$@"
'''

import os
import shutil
from subprocess import call

# the MSVC libraries we want to add TRaP info to
msvc_target_libs = ["%s.lib" % lib for lib in
    ['libcmt', 'libcmtd', 'libcpmt', 'libcpmt1', 'libcpmtd', 'libcpmtd0',
    'libcpmtd1', 'msvcrt', 'msvcrtd', 'msvcprt', 'msvcprtd']]

win_sdk_target_libs = ["%s.lib" % lib for lib in
    ['kernel32', 'user32', 'gdi32', 'winspool', 'shell32', 'ole32',
    'oleauth32', 'uuid', 'comdlg32', 'advapi32']]

def get_files_in_dir(base_path='..', exclude_debug=False):
    files = []
    assert os.path.exists(base_path), "invalid path %s" % base_path
    to_abs_path = lambda f: os.path.abspath(os.path.join(directory, f))
    for directory, dirnames, filenames in os.walk(base_path):
        filenames = map(to_abs_path, filenames)
        files += filenames

    if exclude_debug:
        files = filter(lambda f: 'Debug' not in f, files)

    files = filter(lambda f: '.git' not in f, files)
    return files

def get_exe_path(exe_name='TrapLib.exe'):
    files = get_files_in_dir()
    traplib_exes = filter(lambda f: f.endswith(exe_name), files)
    assert len(traplib_exes), "%s not found" % exe_name
    return traplib_exes[0]

def get_progfiles_dir():
    if os.environ['ARCHITECTURE'] == '64':
        return os.path.abspath('\\Program Files (x86)')
    else:
        return os.path.abspath('\\Program Files')

def get_vs_basedir():
    prog_files = get_progfiles_dir()
    vs_basedirs = os.listdir(prog_files)
    vs_basedirs = filter(lambda d: 'Microsoft Visual Studio' in d, vs_basedirs)

    assert len(vs_basedirs), "Visual Studio installation not found."
     # grab the last VS basedir found to get latest version
    return os.path.join(prog_files, vs_basedirs[-1])

def get_msvc_libs():
    vs_libdir = os.path.join(get_vs_basedir(), "VC\lib")
    assert os.path.exists(vs_libdir), "Visual Studio libraries not found"
    vs_libs = get_files_in_dir(vs_libdir)
    vs_libs = filter(lambda l: os.path.basename(l) in msvc_target_libs, vs_libs)
    # exclude files in subdirs (e.g. amd64, arm, store)
    vs_libs = filter(lambda l: os.path.dirname(l) == vs_libdir, vs_libs)
    return vs_libs

def get_win_sdk_libs():
    prog_files = get_progfiles_dir()
    #FIXME: assumes path is 'Windows Kits\8.1\Lib\winv6.3\um\x86'
    win_sdk_basedir = os.path.join(prog_files, 'Windows Kits', '8.1', 'Lib',
        'winv6.3', 'um', 'x86')
    assert os.path.exists(win_sdk_basedir), "Windows libraries not found"
    win_sdk_libs = get_files_in_dir(win_sdk_basedir)
    win_sdk_libs = filter(lambda l: os.path.basename(l).lower() in win_sdk_target_libs, win_sdk_libs)
    return win_sdk_libs

def set_env_vars():
    """Note: only tested on Windows 8.1 64-bit with VS 2013."""
    lines = ["#!/bin/sh","# set env. variables"]

    # MSVC_LINKER
    link_exe = os.path.join(get_vs_basedir(), "VC", "BIN", "amd64_x86", "link.exe")
    assert os.path.exists(link_exe) and os.path.isfile(link_exe)
    link_exe = link_exe.replace("\\", "/")
    lines.append("export MSVC_LINKER=\"%s\"" % link_exe)

    def cygwinify(path):
        return "/" + path.replace(":", "").replace("\\", "/")

    # PATH
    scpt_path = os.path.dirname(os.path.join(os.getcwd(), __file__))
    exes_path = os.path.join(scpt_path, os.pardir, "Release")
    exes_path = os.path.abspath(exes_path)
    if os.path.exists(exes_path) and os.path.isdir(exes_path):
        lines.append("export PATH=%s:$PATH" % cygwinify(exes_path))
    else:
        exes_path = os.path.join(scpt_path, os.pardir, "Debug")
        exes_path = os.path.abspath(exes_path)
        assert os.path.exists(exes_path) and os.path.isdir(exes_path)
        lines.append("export PATH=%s:$PATH" % cygwinify(exes_path))

    # LIB and LIBPATH
    libs_path = os.path.join(scpt_path, os.pardir, "TrappedMSVCLibs")
    libs_path = os.path.abspath(libs_path)
    assert os.path.exists(libs_path) and os.path.isdir(libs_path)
    lines.append("export LIB=\"%s;\"$LIB" % libs_path)
    lines.append("export LIBPATH=\"%s;\"$LIBPATH" % libs_path)

    outpath = os.path.abspath(os.path.join(scpt_path, "set-buildvars-cygwin.sh"))
    with open(outpath, "w") as fh:
        fh.write("\n".join(lines))
    os.chmod(outpath, 0o755)
    print "Set build environment variables by sourcing %s" % os.path.basename(outpath)

if __name__ == '__main__':

    # figure out the paths to the files we need
    trap_lib_exe = get_exe_path()
    input_libs = get_msvc_libs() + get_win_sdk_libs()

    # make sure the output directory exists
    out_path = os.path.abspath('..\TrappedMSVCLibs')
    if not os.path.isdir(out_path):
        os.mkdir(out_path)
        print 'Created output directory %s...' % out_path

    # invoke traplib.exe on each of the libraries we found
    for lib in input_libs:
        print 'Adding TRaP info to %s' % os.path.basename(lib)
        outfile = os.path.join(out_path, os.path.basename(lib))
        call([trap_lib_exe, lib, outfile])
        # now copy the .pdb to it remains alongside the .lib
        assert lib.lower().endswith('.lib')
        pdb = lib[:-4] + ".pdb"
        if os.path.exists(pdb) and os.path.isfile(pdb):
            shutil.copy2(pdb, out_path)

    set_env_vars()
