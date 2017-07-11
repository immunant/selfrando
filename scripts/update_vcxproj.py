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


def parse():
    """ Construct a parser for this script, return parsed arguments.
    """
    desc = 'Enable/disable selfrando for Visual Studio C/C++ project'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-i', '--input-project', type=str,
                        dest="input_project", required=True,
                        help='Visual Studio Project (.vcxproj) file')
    return parser.parse_args()


def transform_input(input_project):
    if not os.path.exists(input_project):
        print >> sys.stderr, "input file not found: " + input_project
        quit(errno.ENOENT)

    # read vcxproj
    ET.register_namespace('', NAMESPACE_PREFIX)
    tree = ET.parse(input_project)
    root = tree.getroot()

    # configurations: Release|Win32, Debug|x64, etc.
    configurations = list()
    projconfs = root.findall(".//*[@Label='ProjectConfigurations']/" + NAMESPACE_PREFIX + "ProjectConfiguration")
    for projconf in projconfs:
        print projconf
        print projconf.attrib['Include']
        # TODO: add parameter controlling configuration
        if projconf.attrib['Include'] == 'Release|Win32':
            pass

def main():
    args = parse()

    def have_file(fname):
        if not os.path.isfile(fname):
            emsg = "{} not found; run gen_scripts.py and retry.".format(fname)
            print >> sys.stderr, emsg
            quit(errno.ENOENT)
    have_file("TrapLinker32.props")
    have_file("TrapLinker64.props")

    transform_input(args.input_project)


if __name__ == '__main__':
    main()
