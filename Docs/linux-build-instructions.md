# Building the Randomizer and Running it on Linux
To build a load-time self-randomizing program, take the following steps:

- Install the following packages: `scons` and `libelf-dev` (or an equivalent
  `libelf` package on other distributions)
- Run `scons arch=$ARCH` in the `$SELFRANDO` directory (the top directory of this
  repository), where `$ARCH` is one of `x86` or `x86_64`
- Compile the target program with the options `-ffunction-sections` and
  optionally `-m32` (to compile in 32-bit mode
- Link the program with the options `-ffunction-sections -lrandoentry -lselfrando
  -L$SELFRANDO/sconsRelease/$ARCH/bin -Wl,-u,_TRaP_ProgramInfoTable`, or
   alternatively by adding `-wrapper $SELFRANDO/LinuxSymproc/wrapper.py`
- Add TRaP information to binary if not already added, e.g., using the
  `symproc` binary from the SymProc branch (`wrapper.py` performs this
step automatically)
- Run PatchEntry on the binary to fix up the entry points into the program
  (`wrapper.py` also performs this step)
- Set the `LD_LIBRARY_PATH` environment variable to
  `$SELFRANDO/sconsRelease/$ARCH/bin` so the program can access `libselfrando.so`
- Run the target program (should work at this point)


