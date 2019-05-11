
# Preparing to build selfrando

It is assumed that your system already has a working C++ compiler installed. Either of `g++` or `clang++` should work; `gcc` is required to build libelf.

## ... on Debian-based distributions
Install the required dependencies with this command:
  - `# apt-get install -y cmake git make m4 pkg-config zlib1g-dev`

Note, the version of `cmake` included on some Ubuntu releases such as 14.04 and earlier is too old. Try installing the `cmake3` package instead.

**Note**: Selfrando can also be built with `scons`; to do so, install the eponymous package instead of `cmake`:
  - `# apt-get install -y scons  git make m4 pkg-config zlib1g-dev`

## ... on RPM-based distributions

Install the required dependencies with this command:
- `yum -y install cmake git make m4 zlib-devel`

Note, the version of `cmake` included in Centos 7 and earlier is too old. Use the follwing steps to install the `cmake3` package instead.
```
# yum -y install wget
$ wget http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-9.noarch.rpm
# rpm -ihv epel-release-7-9.noarch.rpm
$ yum check-update
# yum -y install cmake3
```

## ... in a virtual machine
Use one of the Ubuntu virtual machines under `Tools/Vagrant`.

# Building Selfrando

## ... with cmake and make
```bash
$ cd $PATH_TO_SELFRANDO_SRC
$ export SR_ARCH=`uname -m | sed s/i686/x86/`
$ cmake . -DSR_DEBUG_LEVEL=env -DCMAKE_BUILD_TYPE=Release -DSR_BUILD_LIBELF=1 \
  -DSR_ARCH=$SR_ARCH -DSR_LOG=console \
  -DSR_FORCE_INPLACE=1 -G "Unix Makefiles" \
  -DCMAKE_INSTALL_PREFIX:PATH=$PWD/out/$SR_ARCH
$ make -j`nprocs --all`
$ make install
```

**Note 1** if you installed the `cmake3` package on Centos, call `cmake3` instead of `cmake` to generate makefiles.

**Note 2** use `-G Ninja` to generate `ninja` build files instead of Makefiles.

### Notable cmake variables
- `SR_DEBUG_LEVEL` must be a number from 0-10 or the string `env`. Zero means no debug output, 10 enables full debug output. If `env` is given, selfrando reads the debugging level from the `SELFRANDO_debug_level` environment variable.
- `SR_ARCH` must be either `x86` (32-bit builds) or `x86_64` (64-bit builds).
- `SR_LOG` can be any of {`default`, `none`, `console`, `file`}. By default log output is written to `/tmp/selfrando.log`; a custom log filename can be specified using the `SR_LOG_FILENAME` variable.
- `SR_RNG` can be either `rand_r` (fast, lower entropy) or `urandom` (slower, higher entropy).
- `SR_FORCE_INPLACE` terminates selfrando if in-place randomization would fail.
- `CMAKE_INSTALL_PREFIX:PATH` controls the install prefix.


## ... with `scons`
```bash
$ cd $PATH_TO_SELFRANDO_SRC
$ export SR_ARCH=`uname -m | sed s/i686/x86/`
$ scons -Q arch=$SR_ARCH LIBELF_PATH=$PWD/libelf/libelf-prefix FORCE_INPLACE=1
```

**Note** The scons build system is no longer being maintained.

# Building programs with selfrando

## ... using the `srenv` wrapper script

Write `/path/to/Tools/Wrappers/srenv` before your build commands. E.g.:
```bash
/path/to/Tools/Wrappers/srenv gcc source.c -o program
/path/to/Tools/Wrappers/srenv make
```

## ... by setting the build flags explicitly

To build with selfrando and link with `ld` (a.k.a. `ld.bfd`), define these flags and use them to pass a custom set of `{C,CXX,LD}FLAGS` to the build system.
```bash
$ export SR_CFLAGS="-ffunction-sections -fPIC -fuse-ld=bfd"
$ export SR_CXXFLAGS=$SR_CFLAGS
$ SR_BIN=/Path/to/selfrando/install/prefix
$ export SR_LDFLAGS="-B$SR_BIN -Wl,-rpath,$SR_BIN -Wl,--gc-sections  -fuse-ld=bfd"
```

**Note 1**: It is best to add `$SR_{C,CXX,LD}FLAGS` flags to the existing `{C,CXX,LD}FLAGS` variables rather than overriding the latter. If this is difficult, consider using the `srenv` wrapper script. The `Tests` folder contains examples of how to build `thttpd`, `nginx`, and `lua` by modifying the build flags.

**Note 2**: To build with selfrando and link with `gold`, substitute `-fuse-ld=bfd` with `-fuse-ld=gold` everywhere.

**Note 3**: If you are building a static binary with `-static`, please add `-Wl,-z,norelro` to your linker flags.
Selfrando is currently incompatible with glibc's RELRO implementation in statically linked binaries,
so the latter needs to be disabled.

## Checking that a binary was built with selfrando

## ... with trapdump
```bash
$ $SR_BIN/trapdump /Path/to/binary
```

## ... with readelf
```bash
$ readelf -x .txtrp /Path/to/binary
```

If you get the below message, the binary is not selfrando enabled:

```
readelf: Warning: Section '.txtrp' was not dumped because it does not exist!
```


These instructions were tested on Ubuntu 14.04, Ubuntu 16.04, and Centos 7. They should work with both GCC and clang/LLVM.
