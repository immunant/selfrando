#
# This file is part of selfrando.
# Copyright (c) 2015-2019 RunSafe Security Inc.
# For license information, see the LICENSE file
# included with selfrando.
#

import re
from os import path
from trap_msvc_libs import *

def set_env_vars(script_dir, selfrando_root):
    cygwin_lines = ["#!/bin/sh","# set env. variables"] # posix shell script
    pshell_lines = [] # powershell script
    batchs_lines = ['@echo off'] # batch file for cmd.exe

    def cygwinify(path):
        return "/" + path.replace(":", "").replace("\\", "/")

    def set_env_var_ps(name, values, update=False):
        assert len(values)
        assert " " not in name
        # make sure we have a list even if it is a singleton
        values = values if type(values) is list else [values]
        stmt = "$env:{}=".format(name)
        for value in values:
            stmt += "\"" + str(value) + "\";"
        if update:
            stmt += "$env:" + name
        return stmt

    def set_env_var_bat(name, values, update=False):
        assert len(values)
        assert " " not in name
        # make sure we have a list even if it is a singleton
        values = values if type(values) is list else [values]
        stmt = "SET {}=".format(name)
        for value in values:
            stmt += "\"" + str(value) + "\";"
        if update:
            stmt += "%" + name + "%"
        return stmt

    # MSVC_LINKER
    link_exe = get_path_to_link_exe()
    pshell_lines.append(set_env_var_ps("MSVC_LINKER_PATH", link_exe))
    batchs_lines.append(set_env_var_bat("MSVC_LINKER_PATH", link_exe))

    link_exe = link_exe.replace("\\", "/") # convert to posix syntax
    cygwin_lines.append("export MSVC_LINKER_PATH=\"%s\"" %
        os.path.dirname(link_exe))

    # PATH to selfrando wrappers for lib.exe and link.exe
    # NOTE: these are always Win32 binaries even on 64 bit systems.
    exes_path = os.path.join(selfrando_root, "Release")
    exes_path = os.path.abspath(exes_path)
    if os.path.exists(exes_path) and os.path.isdir(exes_path):
        pshell_lines.append(set_env_var_ps("PATH", exes_path, True))
        batchs_lines.append(set_env_var_bat("PATH", exes_path, True))
        cygwin_lines.append("export PATH=\"%s\":$PATH" % cygwinify(exes_path))
    else:
        exes_path = os.path.join(selfrando_root, "Debug")
        exes_path = os.path.abspath(exes_path)
        assert os.path.exists(exes_path) and os.path.isdir(exes_path)
        pshell_lines.append(set_env_var_ps("PATH", exes_path, True))
        batchs_lines.append(set_env_var_bat("PATH", exes_path, True))
        cygwin_lines.append("export PATH=\"%s\":$PATH" % cygwinify(exes_path))

    # LIB and LIBPATH
    platform_name = get_platform_name()
    libs_path = os.path.join(selfrando_root, "TrappedMSVCLibs", platform_name)
    libs_path = os.path.abspath(libs_path)
    if not os.path.exists(libs_path):
        os.makedirs(libs_path)
    else:
        assert os.path.isdir(libs_path)

    platform_subdir = 'x64' if platform_name == 'x64' else ''
    randolib_path = os.path.join(selfrando_root, platform_subdir, "Release")
    randolib_path = os.path.abspath(randolib_path)
    randolib_file_path = os.path.join(randolib_path, "RandoLib.lib")
    if not os.path.isfile(randolib_file_path):
        dbg_randolib_path = os.path.join(selfrando_root, platform_subdir, "Debug")
        dbg_randolib_path = os.path.abspath(dbg_randolib_path)
        dbg_randolib_file_path = os.path.join(dbg_randolib_path, "RandoLib.lib")
        if not os.path.isfile(dbg_randolib_file_path):
            print "Error, RandoLib.lib was not found in any of these dirs:\n %s\n %s" % \
                (randolib_path, dbg_randolib_path)
            quit(1)

    pshell_lines.append(set_env_var_ps("LIB", [randolib_path, libs_path], True))
    batchs_lines.append(set_env_var_bat("LIB", [randolib_path, libs_path], True))
    cygwin_lines.append("export LIB=\"%s\"\\;\"%s\"\\;$LIB" %
        (randolib_path, libs_path))

    pshell_lines.append(set_env_var_ps("LIBPATH", [randolib_path, libs_path], True))
    batchs_lines.append(set_env_var_bat("LIBPATH", [randolib_path, libs_path], True))
    cygwin_lines.append("export LIBPATH=\"%s\"\\;\"%s\"\\;$LIBPATH" %
        (randolib_path, libs_path))

    # Store the set-buildvar-* scripts
    cygwin_outpath = "set-buildvars-cygwin-%s.sh" % platform_name
    cygwin_outpath = os.path.abspath(os.path.join(script_dir, cygwin_outpath))
    with open(cygwin_outpath, "w") as fh:
        fh.write("\n".join(cygwin_lines))
    os.chmod(cygwin_outpath, 0o755)

    pshell_outpath = "set-buildvars-%s.ps1" % platform_name
    pshell_outpath = os.path.abspath(os.path.join(script_dir, pshell_outpath))
    with open(pshell_outpath, "w") as fh:
        fh.write("\n".join(pshell_lines))

    batchs_outpath = "set-buildvars-%s.bat" % platform_name
    batchs_outpath = os.path.abspath(os.path.join(script_dir, batchs_outpath))
    with open(batchs_outpath, "w") as fh:
        fh.write("\n".join(batchs_lines))

    # print instructions
    print "Setting build variables in posix shell/powershell/cmd.exe: "
    print " # . {}".format(os.path.basename(cygwin_outpath))
    print " > . .\\{}".format(os.path.basename(pshell_outpath))
    print " > {}".format(os.path.basename(batchs_outpath))


def gen_msbuild_properties(script_dir, sln_dir):
    # python -m pip install mako
    from mako.template import Template

    props_path = path.join(script_dir, "TrapLinker32.props")
    props_templ = Template(filename=props_path + ".mako")
    conf = "Release"
    with open(props_path, "wb") as propfile:
        propfile.write(props_templ.render(SolutionDir=sln_dir, Configuration=conf))

    props_path = path.join(script_dir, "TrapLinker64.props")
    props_templ = Template(filename=props_path + ".mako")
    with open(props_path, "wb") as propfile:
        propfile.write(props_templ.render(SolutionDir=sln_dir, Configuration=conf,
                                          Platform="x64"))

    print "Generated msbuild .props files for inclusion in .vcxproj files."

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    selfrando_root = os.path.abspath(os.path.join(script_dir, os.pardir))
    # sanity check selfrando_root 
    files_in_root = ["LICENSE", "CONTRIBUTING", "CMakeLists.txt", "appveyor.yml"]
    for rfile in files_in_root:
        assert os.path.isfile(os.path.join(selfrando_root, rfile))
    if re.search(r"\s", selfrando_root):
        print "Warning: spaces in path to selfrando"

    set_env_vars(script_dir, selfrando_root)

    # the $(SolutionDir) variable includes trailing backslash
    sln_dir = selfrando_root + "\\"
    gen_msbuild_properties(script_dir, sln_dir)
