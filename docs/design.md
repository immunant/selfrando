# Selfrando Design

Selfrando aims to fulfill the following goals:

1. Randomize code layout at a finer granularity than ASLR.
2. Avoid diversity on disk; randomize in-memory representation.
3. Avoid changes to existing compilers and linkers.
4. Avoid changes to the host operating systems.

Selfrando does not aim to replace other modern mitigations like control-flow integrity and 
sandboxing; in fact, these techniques are complementary. Although selfrando supports Linux, 
Windows, and Android, this document focuses on Linux.

# Building self-randomizing programs

The following figure shows how self-randomizing programs are built:

![selfrando pipeline](img/sr_pipeline.png)

To use selfrando, it is necessary to direct the compiler to use a linker wrapper rather than 
calling the system linker directly. The Linux linker wrapper, called `traplinker`, intercepts 
and processes all linker inputs before passing them on to the system linker (typically `bfd` 
or `gold`). Input files are rewritten as follows:

- relocatable object files (`.o`) are rewritten to include translation and protection (TRaP) 
information which drives the load-time rewriting process. The TRaP information is contained 
in a new section named `.txtrp`; the format of this section is documented in the [TRaP 
specification](TRaP_specification.md).

- static library files (`.a`) are updated by rewriting each object file contained in the 
archive just like object files passed directly to the linker.

- linker scripts are parsed and any references to relocatable object files are processed.

The linker wrapper does not rewrite object files, static libraries, or linker scripts in place. Instead, it creates a copy in the temporary directory of the host system. These files are cleaned when `traplinker` exits.

## Compilation Requirements

Any compiler can be used with selfrando, but the compiler just output each function in a 
separate code (typically this is accomplished by passing `-ffunction-sections`). In addition, 
the compiler must generate position independent code (typically using the `-fPIC` option). 
Note that selfrando cannot currently be used to compile programs with link time optimization. 

## Linker Requirements

Traplinker is command line compatible with recent versions of `bfd` and `gold`. Using 
binutils version 2.28 or later is recommended. See [LinkerOptions.table] for a list of 
currently handled command line options. Nothing in the design of selfrando precludes us from 
adding support for additional options and linkers in the future. 

# Load-time randomization

_TODO_

# Known Issues

- 64-bit operation has been tested more extensively than 32-bit operation.
- See our issue tracker for specific known problems
