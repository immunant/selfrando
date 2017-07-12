#!/usr/bin/env python
#
# This file is part of selfrando.
# Copyright (c) 2015-2017 Immunant Inc.
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
TRAPLINKER64_PROPS = "TrapLinker32.props"
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
    parser.add_argument('-p', '--inplace', action="store_true",
                        dest="inplace", required=False, default=False, 
                        help='Update Visual Studio Project (.vcxproj) file in-place.')
    # TODO: add --configuration and --platform parameters
    args = parser.parse_args()
    if args.inplace and not args.output_project:
        args.output_project = args.input_project
    elif not args.output_project:
        args.output_project = args.input_project + ".out"
    return args


def transform_importgroup(itemgroup):
    """ TODO: support different configurations/platforms

    Transform an ItemGroup XML element so that the entire project
    becomes Selfrando-Enabled.

    Returns True if XML tree was modified; False otherwise.
    """
    imports = itemgroup.findall(NAMESPACE_PREFIX + "Import")
    for _import in imports:
        if "Project" in _import.attrib:
            if _import.attrib['Project'].endswith(TRAPLINKER32_PROPS):
                break
    else:
        # didn't hit a break so we should import TRAPLINKER32_PROPS
        abs_props_path = os.path.join(SCRIPT_ABS_PATH, TRAPLINKER32_PROPS)
        assert os.path.exists(abs_props_path) and not os.path.isdir(abs_props_path)
        proj = {'Project': abs_props_path}
        ET.SubElement(itemgroup, NAMESPACE_PREFIX + "Import", attrib=proj)
        return True  # XML tree modified

    return False # XML tree unchanged


def transform_project(input_project, output_project):
    """ Transform input_project and write the result to output_project.
    """
    if not os.path.exists(input_project):
        print >> sys.stderr, "input file not found: " + input_project
        quit(errno.ENOENT)

    tree_modified = False

    # read vcxproj
    ET.register_namespace('', NAMESPACE)
    tree = ET.parse(input_project)
    root = tree.getroot()

    # TODO: parameterize configuration
    configuration = "Release|Win32"
    attr_condition = "[@Label='PropertySheets']"
    importgroups = root.findall(NAMESPACE_PREFIX + "ImportGroup" + attr_condition)
    if not importgroups:
        print >> sys.stderr, "Error, input file does not have the expected structure."
        quit(errno.EINVAL)
    cond_filter = "'$(Configuration)|$(Platform)'=='{}'".format(configuration)
    for importgroup in importgroups:
        if 'Condition' in importgroup.attrib:
            condition = importgroup.attrib['Condition']
            if condition == cond_filter:
                tree_modified = transform_importgroup(importgroup)
                break
    else: # didn't hit break, need to create new ImportGroup element
        new_importgroup = ET.SubElement(root, 
                                            NAMESPACE_PREFIX + "ImportGroup", 
                                            attrib={'Condition': cond_filter})
        tree_modified = transform_importgroup(new_importgroup)
        assert tree_modified, "Error, tree not modified after inserting new ImportGroup."
        # emsg = "Error, didn't find ImportGroup element for configuration '{}'".format(configuration)
        # print >> sys.stderr, emsg
        # quit(errno.EINVAL)

    if tree_modified:
        tree.write(output_project, encoding='utf-8', xml_declaration=True)
        print "Wrote Selfrando-enabled .vcxproj to " + output_project
    else:
        print os.path.basename(input_project) + " not updated. Selfrando already enabled."


def main():
    args = parse()

    def have_file(fname):
        if not os.path.isfile(fname):
            emsg = "{} not found; run gen_scripts.py and retry.".format(fname)
            print >> sys.stderr, emsg
            quit(errno.ENOENT)
    have_file(TRAPLINKER32_PROPS)
    have_file(TRAPLINKER64_PROPS)

    transform_project(args.input_project, args.output_project)


if __name__ == '__main__':
    main()
