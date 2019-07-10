#!/bin/sh
# 
# This file is part of selfrando.
# Copyright (c) 2015-2019 RunSafe Security Inc.
# For license information, see the LICENSE file
# included with selfrando.
# 
'''which' python2.7 > /dev/null && exec python2.7 "$0" "$@" || exec python "$0"
"$@"
'''

import sys

def generate_options(target, sources):
    with open(str(target), 'w') as out_file:
        out_file.write('std::map<std::string, int (ArgParser::*)(int, const std::string&)> ArgParser::m_arg_table = {\n')
        for s in sources:
            with open(str(s), 'r') as source_file:
                for line in source_file:
                    words = line.split('//')[0].split()
                    if len(words) == 2:
                        out_file.write('{{"{}", &ArgParser::{}}},\n'.format(words[0], words[1]))
                    elif len(words) == 0:
                        pass
                    else:
                        print "Error: cannot parse " + line
                        return 1
        out_file.write('};\n')

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print >>sys.stderr, "Usage: gen_options.py <target> <sources>..."
        sys.exit(-1)

    generate_options(sys.argv[1], sys.argv[2:])

