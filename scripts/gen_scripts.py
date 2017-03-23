#
# This file is part of selfrando.
# Copyright (c) 2015-2017 Immunant Inc.
# For license information, see the LICENSE file
# included with selfrando.
#

import re
from trap_msvc_libs import *

def set_env_vars():
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

    # PATH
    scpt_path = os.path.dirname(os.path.join(os.getcwd(), __file__))
    exes_path = os.path.join(scpt_path, os.pardir, "Release")
    exes_path = os.path.abspath(exes_path)
    if os.path.exists(exes_path) and os.path.isdir(exes_path):
        pshell_lines.append(set_env_var_ps("PATH", exes_path, True))
        batchs_lines.append(set_env_var_bat("PATH", exes_path, True))
        cygwin_lines.append("export PATH=\"%s\":$PATH" % cygwinify(exes_path))
    else:
        exes_path = os.path.join(scpt_path, os.pardir, "Debug")
        exes_path = os.path.abspath(exes_path)
        assert os.path.exists(exes_path) and os.path.isdir(exes_path)
        pshell_lines.append(set_env_var_ps("PATH", exes_path, True))
        batchs_lines.append(set_env_var_bat("PATH", exes_path, True))
        cygwin_lines.append("export PATH=\"%s\":$PATH" % cygwinify(exes_path))

    # LIB and LIBPATH
    platform_name = get_platform_name()
    libs_path = os.path.join(scpt_path, os.pardir, "TrappedMSVCLibs", platform_name)
    libs_path = os.path.abspath(libs_path)
    if not os.path.exists(libs_path):
        os.makedirs(libs_path)
    else:
        assert os.path.isdir(libs_path)

    platform_subdir = 'x64' if platform_name == 'x64' else ''
    randolib_path = os.path.join(scpt_path, os.pardir, platform_subdir, "Release")
    randolib_path = os.path.abspath(randolib_path)
    randolib_file_path = os.path.join(randolib_path, "RandoLib.lib")
    if not os.path.exists(randolib_file_path) or not os.path.isfile(randolib_file_path):
        randolib_path = os.path.join(scpt_path, os.pardir, platform_subdir, "Debug")
        randolib_path = os.path.abspath(randolib_path)
        randolib_file_path = os.path.join(randolib_path, "RandoLib.lib")
        assert os.path.exists(randolib_file_path) and os.path.isfile(randolib_file_path), \
               "Invalid RandoLib.lib location: %s" % randolib_path

    pshell_lines.append(set_env_var_ps("LIB", [randolib_path, libs_path], True))
    batchs_lines.append(set_env_var_bat("LIB", [randolib_path, libs_path], True))
    cygwin_lines.append("export LIB=\"%s\"\\;\"%s\"\\;$LIB" %
        (randolib_path, libs_path))

    pshell_lines.append(set_env_var_ps("LIBPATH", [randolib_path, libs_path], True))
    batchs_lines.append(set_env_var_bat("LIBPATH", [randolib_path, libs_path], True))
    cygwin_lines.append("export LIBPATH=\"%s\"\\;\"%s\";$LIBPATH" %
        (randolib_path, libs_path))

    # Store the set-buildvar-* scripts
    cygwin_outpath = "set-buildvars-cygwin-%s.sh" % platform_name
    cygwin_outpath = os.path.abspath(os.path.join(scpt_path, cygwin_outpath))
    with open(cygwin_outpath, "w") as fh:
        fh.write("\n".join(cygwin_lines))
    os.chmod(cygwin_outpath, 0o755)

    pshell_outpath = "set-buildvars-%s.ps1" % platform_name
    pshell_outpath = os.path.abspath(os.path.join(scpt_path, pshell_outpath))
    with open(pshell_outpath, "w") as fh:
        fh.write("\n".join(pshell_lines))

    batchs_outpath = "set-buildvars-%s.bat" % platform_name
    batchs_outpath = os.path.abspath(os.path.join(scpt_path, batchs_outpath))
    with open(batchs_outpath, "w") as fh:
        fh.write("\n".join(batchs_lines))

    # print instructions
    print "Setting build variables in posix shell/powershell/cmd.exe: "
    print " # . {}".format(os.path.basename(cygwin_outpath))
    print " > . .\\{}".format(os.path.basename(pshell_outpath))
    print " > {}".format(os.path.basename(batchs_outpath))


def gen_msbuild_properties(sln_dir):
    # python -m pip install mako
    from mako.template import Template
    props_templ = Template(filename="TrapLinker32.props.mako")
    conf = "Release"

    with open("TrapLinker32.props", "wb") as propfile:
        propfile.write(props_templ.render(SolutionDir=sln_dir, Configuration=conf))

    props_templ = Template(filename="TrapLinker64.props.mako")
    with open("TrapLinker64.props", "wb") as propfile:
        propfile.write(props_templ.render(SolutionDir=sln_dir, Configuration=conf,
                                          Platform="x64"))

    print "Generated msbuild .props files for inclusion in .vcxproj files."

if __name__ == '__main__':
    sln_dir = os.path.abspath(os.path.join(os.path.curdir, ".."))
    if re.search(r"\s", sln_dir):
        print "Warning: spaces in path to selfrando"

    gen_msbuild_properties(sln_dir)

    set_env_vars()
