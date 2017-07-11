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

def parse():
    """ Construct a parser for this script, return parsed arguments.
    """
    desc = 'Enable/disable selfrando for Visual Studio C/C++ project'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-i', '--input-project', type=str,
                        dest="input_project", required=True,
                        help='Visual Studio Project (.vcxproj) file')
    return parser.parse_args()


def frobble_inputfile():
    pass

def main():
    args = parse()

    input_project = args.input_project
    if not os.path.exists(input_project):
        print >> sys.stderr, "intput file not found: " + input_project
        quit(errno.ENOENT)


if __name__ == '__main__':
    main()
   