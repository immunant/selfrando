#!/usr/bin/env python
#
# This file is part of selfrando.
# Copyright (c) 2015-2019 RunSafe Security Inc.
# For license information, see the LICENSE file
# included with selfrando.
#

import argparse
import os
import sys
import errno
import xml.etree.ElementTree as ET

NAMESPACE = 'http://schemas.microsoft.com/developer/msbuild/2003'
NAMESPACE_PREFIX = "{" + NAMESPACE + "}"
TRAPLINKER32_PROPS = "TrapLinker32.props"
TRAPLINKER64_PROPS = "TrapLinker64.props"
SCRIPT_ABS_PATH = os.path.abspath(os.path.dirname(__file__))

def parse():
    """ Construct a parser for this script & return parsed arguments.
    """
    desc = 'Enable/disable selfrando for Visual Studio C/C++ project'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-i', '--input-project', type=str,
                        dest="input_project", required=True,
                        help='Input Visual Studio Project (.vcxproj) file')
    o_help = 'Output Visual Studio Project (.vcxproj) file. Overrides --inplace.'
    parser.add_argument('-o', '--output-project', type=str,
                        dest="output_project", required=False, default=None,
                        help=o_help)
    c_help = "Configuration for which to enable/disable selfrando (default: %(default)s)"
    parser.add_argument('-c', '--configuration', type=str,
                        dest="configuration", required=False, default="Release",
                        help=c_help)
    p_help = "Platform for which to enable/disable selfrando (default: %(default)s)"
    parser.add_argument('-p', '--platform', type=str,
                        dest="platform", required=False, default="Win32",
                        help=p_help)
    parser.add_argument('-x', '--inplace', action="store_true",
                        dest="inplace", required=False, default=False,
                        help='Update Visual Studio Project (.vcxproj) file in-place.')
    l_help = 'List project configurations in Visual Studio Project (.vcxproj) file.'
    parser.add_argument('-l', '--list-configurations', action="store_true",
                        dest="list_configurations", required=False, default=False,
                        help=l_help)
    # TODO: add --disable option
    args = parser.parse_args()
    if args.inplace and not args.output_project:
        args.output_project = args.input_project
    elif not args.output_project:
        args.output_project = args.input_project + ".out"
    return args


def transform_importgroup(args, itemgroup):
    """ TODO: support different configurations/platforms

    Transform an ItemGroup XML element so that the entire project
    becomes Selfrando-Enabled.

    Returns True if XML tree was modified; False otherwise.
    """
    traplinker_props = TRAPLINKER64_PROPS \
                       if args.platform.lower() in ["x64", "amd64"] \
                       else TRAPLINKER32_PROPS
    print "Importing {} into {} ".format(traplinker_props, 
                                         os.path.basename(args.input_project))
    print args.platform
    imports = itemgroup.findall(NAMESPACE_PREFIX + "Import")
    for _import in imports:
        if "Project" in _import.attrib:
            if _import.attrib['Project'].endswith(traplinker_props):
                break
    else:
        # didn't hit a break so we should import traplinker_props
        abs_props_path = os.path.join(SCRIPT_ABS_PATH, traplinker_props)
        assert os.path.exists(abs_props_path) and not os.path.isdir(abs_props_path)
        proj = {'Project': abs_props_path}
        ET.SubElement(itemgroup, NAMESPACE_PREFIX + "Import", attrib=proj)
        return True  # XML tree modified

    return False # XML tree unchanged


def transform_project(args):
    """ Transform input_project and write the result to output_project.
    """

    tree_modified = False

    # read vcxproj
    ET.register_namespace('', NAMESPACE)
    tree = ET.parse(args.input_project)
    root = tree.getroot()

    # construct configuration; default: "Release|Win32" 
    configuration = "{configuration}|{platform}" \
                    .format(configuration=args.configuration,
                            platform=args.platform)
    attr_condition = "[@Label='PropertySheets']"
    importgroups = root.findall(NAMESPACE_PREFIX + "ImportGroup" + attr_condition)
    if not importgroups:
        print >> sys.stderr, "Error: input file does not have the expected structure."
        quit(errno.EINVAL)
    cond_filter = "'$(Configuration)|$(Platform)'=='{}'".format(configuration)
    for importgroup in importgroups:
        if 'Condition' in importgroup.attrib:
            condition = importgroup.attrib['Condition']
            if condition == cond_filter:
                tree_modified = transform_importgroup(args, importgroup)
                break
    else: # didn't hit break, need to create new ImportGroup element
        new_importgroup = ET.SubElement(root,
                                        NAMESPACE_PREFIX + "ImportGroup",
                                        attrib={'Condition': cond_filter})
        tree_modified = transform_importgroup(args, new_importgroup)
        assert tree_modified, "Error: tree not modified after inserting new ImportGroup."

    if tree_modified:
        tree.write(args.output_project, encoding='utf-8', xml_declaration=True)
        print "Wrote Selfrando-enabled .vcxproj to " + args.output_project
    else:
        print os.path.basename(args.input_project) + \
            " not updated. Selfrando already enabled."


def list_configurations(args):
    ET.register_namespace('', NAMESPACE)
    tree = ET.parse(args.input_project)
    root = tree.getroot()
    xpath = ".//*[@Label='ProjectConfigurations']/{ns}ProjectConfiguration" \
            .format(ns=NAMESPACE_PREFIX) 
    proj_configs = root.findall(xpath)
    if proj_configs:
        for config in proj_configs:
            print config.attrib['Include']
    else:
        print >> sys.stderr, "Error: no project configurations found in " + \
                             os.path.basename(args.input_project)

def main():
    """ Script entrypoint """
    args = parse()

    # begin sanity checking
    def have_file(fname):
        """ Check if named file is present in same dir as script. """
        if not os.path.isfile(os.path.join(SCRIPT_ABS_PATH, fname)):
            emsg = "{} not found; run gen_scripts.py and retry.".format(fname)
            print >> sys.stderr, emsg
            quit(errno.ENOENT)
    have_file(TRAPLINKER32_PROPS)
    have_file(TRAPLINKER64_PROPS)

    if not os.path.exists(args.input_project):
        print >> sys.stderr, "Error: input file not found: " + args.input_project
        quit(errno.ENOENT)
    # end sanity checking

    if args.list_configurations:
        list_configurations(args)
        quit(0)

    transform_project(args)


if __name__ == '__main__':
    main()
