# Self-Randomizing Binaries

Self-randomizing binaries programs, using relocation and section information from .OBJ files. The goal is to build a **practical** randomization solution that

- is compatible with existing distribution mechanisms (everybody gets single binary)
- adds little or no performance overhead or latency
- avoids need to modify existing compilers, assemblers, loaders, or OS.
- delivers far better security than ASLR
- works on Windows, OS X, and Linux

## Build instructions

For build instructions, read `linux-build-instructions.md` and
`windows-build-instructions.md` inside the `Docs` directory.
