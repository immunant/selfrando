# Copyright (c) 2015-2019 RunSafe Security Inc.
import sys
import os

vars = Variables(None, ARGUMENTS)
vars.Add(EnumVariable(('TARGET_ARCH', 'arch'), 'Target architecture', 'x86_64',
                      allowed_values=('x86', 'x86_64', 'arm', 'arm64')))
vars.Add(EnumVariable('LOG', 'Logging to perform', 'default',
                      allowed_values=('default', 'none', 'console', 'file', 'system')))
vars.Add('LOG_FILENAME', 'Log file to output to', '/tmp/selfrando.log')
vars.Add(BoolVariable('LOG_APPEND', 'Append to log instead of replacing it', 0))
vars.Add('DEBUG_LEVEL', 'Debugging level (0-10); set to "env" to control via environment variable', 0)
# TODO: make it a PathVariable???
vars.Add('ANDROID_NDK', 'Android NDK directory (build libs for Android)', None)
vars.Add('LIBELF_PATH', 'Path to directory containing libelf.so (if not using system libelf)', None)
vars.Add(BoolVariable('OPTIMIZED', 'Enable optimized build of traplinker.', 1))
vars.Add('DEBUG_SEED', 'Fixed seed to use for debugging', False) # We need to use False as the default since None means "no default"
vars.Add(BoolVariable('FORCE_INPLACE', 'Terminate execution (via failed assertion) if in-place randomization would fail', 1))
vars.Add(EnumVariable('WRITE_LAYOUTS', 'After randomization, write layout files to /tmp/',
                      'no', allowed_values=('no', 'env', 'always')))
vars.Add(EnumVariable('DELETE_LAYOUTS', 'Delete the layout file on process exit',
                      'no', allowed_values=('no', 'env', 'always')))
vars.Add(EnumVariable('RNG', 'Random number generator to use',
                      'chacha', allowed_values=('chacha', 'rand_r', 'urandom')))
vars.Add(BoolVariable('NO_MREMAP', 'Avoid using mremap() to reallocate memory', 0))

def decode_debug_level(var):
    if var == 'env':
        return 0
    try:
        return int(var)
    except ValueError:
        print "DEBUG_LEVEL value must be a number!"
        raise

# Top build file for scons
env = Environment(variables=vars,
                  ENV = {'PATH': os.environ['PATH']})
                  #CXX = 'clang++')
print "Building self-rando for platform '%s' on '%s'" % (env['PLATFORM'], env['TARGET_ARCH'])

SUBDIRS = ['Support', 'RandoLib', 'TrapLinker', 'TrapInfo', 'TrapLibs']
OUTDIR = 'out' # TODO: make this into an option
INSTALL_PATH = '%s/%s/bin' % (OUTDIR, env['TARGET_ARCH'])

arch_32bit = env['TARGET_ARCH'] in ['x86', 'arm']
defines = {
    'RANDOLIB_ARCH': '${TARGET_ARCH}',
    'RANDOLIB_ARCH_SIZE': 32 if arch_32bit else 64,
    'RANDOLIB_IS_ANDROID': 1 if ('ANDROID_NDK' in env and env['ANDROID_NDK']) else 0,
    'RANDOLIB_LOG_FILENAME': '"${LOG_FILENAME}"',
    'RANDOLIB_LOG_APPEND': 1 if env['LOG_APPEND'] else 0,
    'RANDOLIB_INSTALL_PATH': '"{}"'.format(INSTALL_PATH),
    'RANDOLIB_DEBUG_LEVEL': decode_debug_level(env['DEBUG_LEVEL']),
    'RANDOLIB_DEBUG_LEVEL_IS_ENV': 1 if env['DEBUG_LEVEL'] == 'env' else 0,
    'RANDOLIB_FORCE_INPLACE': 1 if env['FORCE_INPLACE'] else 0,
    'RANDOLIB_WRITE_LAYOUTS': { 'no': 0, 'env': 1, 'always': 2 }[env['WRITE_LAYOUTS']],
    'RANDOLIB_DELETE_LAYOUTS': { 'no': 0, 'env': 1, 'always': 2 }[env['DELETE_LAYOUTS']],
    'RANDOLIB_NO_MREMAP': 1 if env['NO_MREMAP'] else 0,
}
defines['RANDOLIB_IS_%s' % env['PLATFORM'].upper()] = 1
defines['RANDOLIB_IS_%s' % env['TARGET_ARCH'].upper()] = 1
defines['RANDOLIB_LOG_TO_%s' % env['LOG'].upper()] = 1
if env['DEBUG_SEED'] is not False:
    defines['RANDOLIB_DEBUG_SEED'] = env['DEBUG_SEED']
defines['RANDOLIB_RNG_IS_%s' % env['RNG'].upper()] = 1

env.Append(CPPDEFINES = defines)

if env['PLATFORM'] == 'win32':
    env.Append(CCFLAGS = '/EHsc') # C++ exception handling support
    env.Append(CCFLAGS = '/W3')   # Show lots of warnings
    env.Append(CCFLAGS = '/O2')   # Optimize the code
    env.Append(CCFLAGS = '/Oi')   # Enable inlining of intrinsic functions
    env.Append(CCFLAGS = '/Oy-')  # Disable frame pointer optimization
    env.Append(CCFLAGS = '/Gy')   # Function-level linking (with COMDAT)
    env.Append(CCFLAGS = '/Gm-')  # Disable minimal rebuild
    env.Append(CCFLAGS = '/Zc:wchar_t')
    env.Append(CCFLAGS = '/Zc:forScope')
    env.Append(CCFLAGS = '/analyze-') # No code analysis
    env.Append(CCFLAGS = '/MD')   # Multithreaded support (use MSVCRT.DLL)
    env.Append(CCFLAGS = '/DEBUG')# Enable debugging info

    # Pre-compiled headers
    #env.Append(CCFLAGS = '/Yc"stdafx.h"')
    #env.Append(CCFLAGS = '/Fp"TODO"')
    #env.Append(CCFLAGS = '/Fo"TODO"') # Needed for /Zi
    #env.Append(CCFLAGS = '/Zi')   # Generate debug info

    # Preprocessor defines
    env.Append(CPPDEFINES = 'WIN32')
    env.Append(CPPDEFINES = 'NDEBUG')
    env.Append(CPPDEFINES = '_CONSOLE')
    env.Append(CPPDEFINES = '_LIB')
    env.Append(CPPDEFINES = '_UNICODE')
    env.Append(CPPDEFINES = 'UNICODE')

    # Linker options
    env.Append(LINKFLAGS = '/MACHINE:X86')       # Build for 32-bit Windows
    env.Append(LINKFLAGS = '/INCREMENTAL:NO')    # Disable incremental linking
    env.Append(LINKFLAGS = '/SUBSYSTEM:CONSOLE') # Build a console app
    env.Append(LINKFLAGS = '/OPT:REF')           # Eliminate never-ref functions
    env.Append(LINKFLAGS = '/OPT:ICF')           # Identical COMDAT folding
    env.Append(LINKFLAGS = '/SAFESEH')
    env.Append(LINKFLAGS = '/MANIFEST')          # Manifest file to make UAC happy
    env.Append(LINKFLAGS = '/MANIFEST:EMBED')

    # Librarian options
    # empty for now

    # Link-time code generation options (disabled, not much impact)
    #env.Append(CCFLAGS   = '/GL')   # Whole-program optimization
    #env.Append(LINKFLAGS = '/LTCG') # Link-time code gen
    #env.Append(ARFLAGS   = '/LTCG') # Link-time code gen

elif env['PLATFORM'] == 'posix':
    if env['OPTIMIZED']:
        env.Append(CCFLAGS = '-O2')
    env.Append(CCFLAGS = '-fno-omit-frame-pointer')
    env.Append(CCFLAGS = '-g') # Enable debugging
    env.Append(CCFLAGS = '-Wall')
    env.Append(CCFLAGS = '-Wextra')
    env.Append(CCFLAGS = '-Wno-unused-parameter')
    env.Append(CCFLAGS = '-Wpointer-arith')

    # C++-specific flags
    env.Append(CXXFLAGS = '-std=c++11')

    # disable execstack
    env.Append(ASFLAGS = '-Wa,--noexecstack')
    env.Append(LINKFLAGS = '-Wl,-z,noexecstack')

    # print vars

Export('env')
for subdir in SUBDIRS:
    files = SConscript('src/%s/SConscript' % subdir, variant_dir='%s/%s/%s' % (OUTDIR, env['TARGET_ARCH'], subdir), duplicate=0)
    Install(INSTALL_PATH, files)
 
