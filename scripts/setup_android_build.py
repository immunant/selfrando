#
# This file is part of selfrando.
# Copyright (c) 2015-2019 RunSafe Security Inc.
# For license information, see the LICENSE file
# included with selfrando.
#

import os
import errno
import sys
import subprocess
import argparse

ARCH_PATHS = {
        'arm'   : ('arm', 'arm-linux-androideabi', '4.9'),
        'arm64' : ('aarch64', 'aarch64-linux-android', '4.9'),
        # TODO: x86 and x86_64 (tricky, Android uses the same linker for both)
}

arg_parser = argparse.ArgumentParser(description='Set up selfrando paths in Android build system.')
arg_parser.add_argument('arch', metavar='ARCH', choices=ARCH_PATHS.keys(),
                        help='The architecture to set up the build for')
arg_parser.add_argument('android_path', metavar='PATH',
                        help='Path to Android source code')
args = arg_parser.parse_args()

selfrando_topdir = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), '..'))
selfrando_bindir = os.path.join(selfrando_topdir, 'out', args.arch, 'bin')
selfrando_ld = os.path.join(selfrando_bindir, 'ld')
if not os.path.exists(selfrando_ld):
    print >>stderr, "Cannot find selfrando linker at '%s'" % selfrando_ld
    os.exit(-1)

android_arch, android_prefix, android_gccver = ARCH_PATHS[args.arch]
android_prebuilts_topdir = os.path.join(os.path.realpath(args.android_path),
                                        'prebuilts', 'gcc', 'linux-x86',
                                        android_arch, '%s-%s' % (android_prefix, android_gccver))
if not os.path.exists(android_prebuilts_topdir):
    print >>stderr, "Cannot find Android compiler prebuilts in '%s'" % android_prebuilts_topdir
    os.exit(-1)

def symlink_forced(source, target):
    try:
        os.symlink(source, target)
    except OSError, e:
        if e.errno == errno.EEXIST:
            os.remove(target)
            os.symlink(source, target)

# $TOPDIR/bin/$PREFIX-ld => $PREFIX-ld.traplinker => $SELFRANDO_BINDIR/ld
symlink_forced(selfrando_ld,
               os.path.join(android_prebuilts_topdir, 'bin',
                            '%s-ld.traplinker' % android_prefix))
symlink_forced('%s-ld.traplinker' % android_prefix,
               os.path.join(android_prebuilts_topdir, 'bin',
                            '%s-ld' % android_prefix))

# $TOPDIR/$PREFIX/bin/ld => ld.traplinker => $SELFRANDO_BINDIR/ld
symlink_forced(selfrando_ld,
               os.path.join(android_prebuilts_topdir, android_prefix,
                           'bin', 'ld.traplinker'))
symlink_forced('ld.traplinker',
               os.path.join(android_prebuilts_topdir, android_prefix,
                           'bin', 'ld'))

