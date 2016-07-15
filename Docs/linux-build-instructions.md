# Building the Randomizer and Running it on Linux
To build a load-time self-randomizing program, take the following steps:

- Install the following packages: `scons`, `pkg-config`, `libelf-dev`, and `zlib1g-dev` (or equivalent packages on other distributions). Alternatively, you can use a Vagrant virtual machine (see `Tools/Vagrant`).
- Run `scons` in the top directory of this repository. If you are on 32-bit `x86`, use `scons arch=x86`.
- Write `/path/to/Tools/Wrappers/GCC/srenv` before your build commands. E.g.:
```bash
/path/to/Tools/Wrappers/GCC/srenv gcc source.c -o program
/path/to/Tools/Wrappers/GCC/srenv make
```
- Run the program.

### Using Clang
If you prefer Clang you can use it as well. Simply build selfrando using `scons ALT_CC=clang ALT_CXX=clang++`, then write `/path/to/Tools/Wrappers/Clang/srenv` before your build commands. The GCC build and the Clang build are located in different directories and do not conflict with each other.

These instructions were tested on Ubuntu 14.04 and 16.04.
