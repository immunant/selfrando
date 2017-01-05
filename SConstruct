import sys
import os

vars = Variables(None, ARGUMENTS)
vars.Add(EnumVariable(('TARGET_ARCH', 'arch'), 'Target architecture', 'x86_64',
                      allowed_values=('x86', 'x86_64', 'arm', 'arm64')))
# TODO: make it a PathVariable???
vars.Add('ANDROID_NDK', 'Android NDK directory (build libs for Android)', None)
vars.Add(BoolVariable('IS_GITIAN', 'Add additional headers for a build in Gitian', False))
vars.Add( 'ADDN_CCFLAGS',   'Additional CCFLAGS',  None)
vars.Add('ADDN_LINKFLAGS', 'Additional LINKFLAGS', None)
vars.Add('ALT_CC', 'Alternate C compiler', None)
vars.Add('ALT_CXX', 'Alternate C++ compiler', None)
vars.Add('FUNCTION_PRESERVE_ALIGN',
    'Preserve alignment up to x bits', 2)

# Top build file for scons
SUBDIRS = ['PatchEntry', 'RandoLib']
OUTDIR = 'sconsRelease' # TODO: make this into an option

env = Environment(variables=vars,
                  ENV = {'PATH': os.environ['PATH']})
print "Building selfrando for platform '%s' on '%s'" % (env['PLATFORM'], env['TARGET_ARCH'])

if os.getenv("CXX"):
    env["CXX"] = os.getenv("CXX")
    env["CC"] = env["CXX"]
if os.getenv("CC"):
    env["CC"] = os.getenv("CC")
if  'ADDN_CCFLAGS'  in env and env[ 'ADDN_CCFLAGS' ]:
    env.Append( CCFLAGS =  env[ 'ADDN_CCFLAGS' ])
if 'ADDN_LINKFLAGS' in env and env['ADDN_LINKFLAGS']:
    env.Append(LINKFLAGS = env['ADDN_LINKFLAGS'])
if 'ALT_CC'  in env and env['ALT_CC']:
    env.Replace(CC  = env['ALT_CC'])
if 'ALT_CXX' in env and env['ALT_CXX']:
    env.Replace(CXX = env['ALT_CXX'])


defines = {
    'RANDOLIB_ARCH': '${TARGET_ARCH}',
}

arch_32bit = env['TARGET_ARCH'] in ['x86', 'arm']
defines['RANDOLIB_IS_%s' % env['TARGET_ARCH'].upper()] = 1
defines['RANDOLIB_ARCH_SIZE'] = 32 if arch_32bit else 64

if 'ANDROID_NDK' in env and env['ANDROID_NDK']:
    defines['RANDOLIB_IS_ANDROID'] = True

env.Append(CPPDEFINES = defines)
if env['PLATFORM'] == 'win32':
    SUBDIRS.extend(['LibWrapper', 'LinkWrapper', 'TrapCommon', 'TrapLib', 'TrapObj', 'WrapperCommon'])

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
    SUBDIRS.append('LinuxSymproc')

    env.Append(CCFLAGS = '-O2')
    env.Append(CCFLAGS = '-fno-omit-frame-pointer')
    env.Append(CCFLAGS = '-g') # Enable debugging

    # C++-specific flags
    env.Append(CXXFLAGS = '-std=c++11')

    # disable execstack
    env.Append(ASFLAGS = '-Wa,--noexecstack')
    env.Append(CCFLAGS = '-Wl,-z,noexecstack')

    # print vars

Export('env')
compdir = env['CC'].split()[-1].split('/')[-1].split('\\')[-1]
for subdir in SUBDIRS:
    files = SConscript('src/%s/SConscript' % subdir, variant_dir='%s/%s/%s/%s' % (OUTDIR, env['TARGET_ARCH'], compdir, subdir), duplicate=0)
    Install('%s/%s/%s/bin' % (OUTDIR, env['TARGET_ARCH'], compdir), files)
