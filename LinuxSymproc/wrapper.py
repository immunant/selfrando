#!/usr/bin/env python2
import os
import sys
import argparse
import subprocess
import shutil

SUBCOMMANDS = ['cc1', 'cc1plus', 'as', 'collect2']
BLACKLIST = [
    'a.out',
    'conftest',
    '/tmp'
]

# todo: make this more general
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
BASE_DIR = os.path.join(BASE_DIR, os.pardir, 'sconsRelease', 'x86_64', 'bin')
BASE_DIR = os.path.abspath(BASE_DIR)

SYMPROC = os.path.join(BASE_DIR, 'SymProc')
PATCHENTRY = os.path.join(BASE_DIR, 'PatchEntry')

# log_filename = sys.argv[1]
# log = open(log_filename, 'a')

args = sys.argv[1:]

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-o', '--output', default='a.out')
parsed_args, unknown_args = parser.parse_known_args(args)

output_file = parsed_args.output
map_file = output_file + '.map'

command=None
for cmd in SUBCOMMANDS:
    if args[0].endswith(cmd):
        command=cmd

# sys.stderr.write(args[0] + '\n')

run_symproc = False
run_patchentry = False
if command == 'collect2':
    if True not in [output_file.startswith(x) for x in BLACKLIST]:
        run_symproc = True
        run_patchentry = True
        args.append('-Map=' + map_file)
        #args.extend(['-L' + BASE_DIR, '-lrandoentry', '-lselfrando'])
        args.extend(['-L' + BASE_DIR, '-lselfrando'])
        args.extend(['-u', '_TRaP_ProgramInfoTable'])
        args.extend(['-u', '_randolib_init', '-init', '_randolib_init'])
        # log.write(map_file + '\n')

if command in ['cc1', 'cc1plus']:
    args.append('-ffunction-sections')


# sys.stderr.write(' '.join(args) + '\n')

exit_status = subprocess.call(args)

if run_symproc:
    subprocess.call([SYMPROC, output_file, map_file])

if run_patchentry:
    subprocess.call([PATCHENTRY, output_file] + '.rand.out')

if exit_status == 0 and run_symproc:
    shutil.move(output_file, output_file + '.orig')
    shutil.move(output_file + '.rand.out', output_file)

sys.exit(exit_status)
