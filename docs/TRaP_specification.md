TRaP Format Specification
=========================

A TRaP section describes features of executable code that are necessary to
correctly randomize or rewrite the executable. TRaP information at least
contains the location of relevant symbols and necessary relocations to move
those symbols in memory.

## Version History

*Version 1.0* - This version. Based on textrap.txt used in selfrando and
linker/loader based randomization.

## Structure

TRaP section names shall begin with `.txtrp`. Executables should normally
contain a single TRaP section, without any suffix after `.txtrp`.

A TRaP section contains a TRaP header, optionally followed by a vector of
relocations, followed by one or more consecutive TRaP records. All values are
little-endian, unless otherwise specified.

## TRaP Header

A TRaP header contains a file format version and a flags field describing the
features contained in this TRaP section. The header has the following structure:

```c
struct TRaPHeader {
  unsigned int Version : 4;
  unsigned int Flags   : 12;

  // List of relocation addresses (absolute, PC-relative, and other kinds)
  // that point to code, but are outside any executable section.
  // Only present if flag bit 0x20 is set.
  OPTIONAL TrapRelocVector NonExecRelocs;

  // Pointer size (in bits) of target architecture for this binary.
  // Only present if flag bit 0x200 is set.
  OPTIONAL ULEB128 PointerSize;
};
```

Available values for `Version`:

| `Version` field | Specification Version |
|-----------------|-----------------------|
| 1               | 1.0                   |

The `Flags` field is a bitwise OR of 0 or more of the following values:

| Bit | Hex Value | Description                                                 |
|-----|-----------|-------------------------------------------------------------|
| 0   | 0x000001  | Starting points of functions are marked (used in the original randomization, function reordering) |
| 1   | 0x000002  | Records are pre-sorted                                      |
| 2   | 0x000004  | Symbols also have size information (symbols vector is a vector of ULEB128 pairs) |
| 3   | 0x000008  | Records also contain information on data references (which symbols have their address taken) |
| 4   | 0x000010  | Records contain relocations                                 |
| 5   | 0x000020  | Trap information contains vector of relocations outside executable sections |
| 6   | 0x000040  | Records contain padding                                     |
| 7   | 0x000080  | All addresses (FirstSymAddr and others) are PC-relative (pointer-sized signed offsets from the memory location where they're stored) |
| 8   | 0x000100  | Symbols also have alignment information (power-of-2 values) |
| 9   | 0x000200  | Header has pointer size information                         |
| 10  | 0x000400  |  All addresses are relative to a base address, e.g., the address of .got.plt on Linux |

These flags are described in more detail in other sections when they are
relevant.


## Non-text Relocation Vector

If `Flags` bit 6 is set, the TRaP section next contains a TRaPRelocVector of
code references or relocations outside executable sections, e.g., function
pointers inside `.rodata` or `.data`, such as C++ vtables. This vector shall be
in sorted order of virtual address. See the *Vector Types* for format details.

## TRaP Records

Each record contains information about one executable section from the object
file or library, describing its exported symbols and relocations.
Alternatively, there can be one record per function, or a single record for the
entire program.  In this document, "symbol" refers to any memory object that is
used in randomization, e.g., functions, basic blocks or more.  For example, in
the context of function reordering "symbol" means "function".

TRaP records have the following structure:
```c
struct TRaPRecord {
    // The memory address of the first symbol in this record
    // On Windows, this is a RVA (address relative to image base, with a DIR32NB
    // relocation entry associated)
    void *FirstSymAddr;

    // Information about the first symbol in this record
    // (in most cases, its offset will be 0, since most executable sections start with a function)
    TRaPSymbol FirstSymbol;

    // A list of all other program symbols described by this record
    TRaPSymbolVector Symbols;

    // A list of all relocations inside this section that need to be patched
    // after randomization
    // This field is only present if bit 4 of the header is set.
    OPTIONAL TRaPRelocVector Relocs;

    // A list of all program locations whose addresses are taken as data
    // addresses, e.g., memory operands inside instructions.
    // This field is only present if bit 3 of the header is set.
    OPTIONAL TRaPVector DataRefs;

    // If padding is specified in the header (bit 6 of the header), this is the
    // starting offset and size of the padding.
    OPTIONAL ULEB128 PaddingOffset;
    OPTIONAL ULEB128 PaddingSize;
};
```

## Vector Types

### TRaPVector

The TRaPVector data structure encodes a list of strictly increasing offsets from
the start of the current executable section.  Each offset is stored as a ULEB128
encoding of its distance from the previous offset.  The vector is terminated
with a single 0-byte (since the offsets are distinct, no 0-distance is ever
encoded).

C-style structure:
```c
typedef ULEB128[] TRaPVector;
```

Example: The decimal offsets [5, 12, 17, 33] are encoded (in hexadecimal) as the
stream "05 07 05 10 00".

### TRaPSymbolVector

Symbols are encoded using the TRaPSymbolVector.
This structure encodes a list of TRaPSymbol aggregate values, terminated by a
TRaPSymbol element full of zeroes.
The first ULEB128 value in each pair encodes
the offset of the current symbol from the end of the previous one, while the
other values in the pair encode the optional size and alignment.

C-style structure:
```c
struct TRaPSymbol {
    // Offset of this symbol from the previous one.
    ULEB128 SymbolOffset;

    // Size of this symbol.
    // This field is only present if bit 0x4 inside the header is set.
    OPTIONAL ULEB128 SymbolSize;

    // Alignment of this symbol, represented as the base-2 logarithm.
    // This field is only present if bit 0x100 inside the header is set.
    OPTIONAL ULEB128 SymbolAlignmentLog2;
};

typedef TRaPSymbol[] TRaPSymbolVector;
```

Example: The encoding for two symbols at addresses 0x10 and 0x20 and sizes 6 and
10 (0xA in hex) is (starting from address 0x0): "10 06 0A 0A 00 00".

### TRaPRelocVector

Relocations are encoded using the TRaPRelocVector structure, which is a vector
similar to TRaPSymbolVector. TRaPRelocVector also encodes a list of
ULEB128-encoded pairs of values, where the first value represents the address of
a relocation (delta-encoded from the previous one), and the second component of
the pair encodes the relocation type (which is architecture- and OS-specific, we
currently use the type encodings for PE/ELF files).  Additionally, some
relocation pairs may be followed by extra information, e.g., PC-relative
relocations can encode the symbol (S) or addend (A) values after the pair of
ULEBs. The vector ends in a pair of zeroes.

C-style structure:
```c
struct TRaPReloc {
    ULEB128 Offset;
    ULEB128 Type;
    
    OPTIONAL void* Symbol;
    OPTIONAL SLEB128 Addend;
};

typedef TRaPReloc[] TRaPRelocVector;
```

Addend is a signed LEB128 value. Symbol and/or Addend is used for the following relocations:

| Relocation                    | Symbol? | Addend? |
|-------------------------------|---------|---------|
| R_X86_64_PC32                 | no      | yes     |
| R_X86_64_PLT32                | no      | yes     |
| R_X86_64_GOTPC32              | no      | yes     |
| R_X86_64_GOTPCREL             | no      | yes     |
| R_X86_64_GOTPCRELX            | no      | yes     |
| R_X86_64_REX_GOTPCRELX        | no      | yes     |
| R_X86_64_TLSGD                | no      | yes     |
| R_X86_64_TLSLD                | no      | yes     |
| R_X86_64_GOTTPOFF             | no      | yes     |
| R_X86_64_GOTPC32_TLSDESC      | no      | yes     |
| R_X86_64_PC64                 | no      | yes     |
| R_X86_64_GOTPCREL64           | no      | yes     |
| R_X86_64_GOTPC64              | no      | yes     |
| R_ARM_REL32                   | no      | yes     |
| R_ARM_GOTOFF32                | no      | yes     |
| R_ARM_BASE_PREL               | no      | yes     |
| R_ARM_PREL31                  | no      | yes     |
| R_ARM_GOT_PREL                | no      | yes     |
| R_ARM_TARGET2                 | no      | yes     |
| R_ARM_MOVW_ABS_NC             | yes     | yes     |
| R_ARM_MOVT_ABS                | yes     | yes     |
| R_ARM_THM_MOVW_ABS_NC         | yes     | yes     |
| R_ARM_THM_MOVT_ABS            | yes     | yes     |
| R_AARCH64_PREL32              | no      | yes     |
| R_AARCH64_PREL64              | no      | yes     |
| R_AARCH64_ADR_PREL_PG_HI21    | yes     | yes     |
| R_AARCH64_ADR_PREL_PG_HI21_NC | yes     | yes     |
| R_AARCH64_ADD_ABS_LO12_NC     | yes     | yes     |
| R_AARCH64_LDST8_ABS_LO12_NC   | yes     | yes     |
| R_AARCH64_LDST16_ABS_LO12_NC  | yes     | yes     |
| R_AARCH64_LDST32_ABS_LO12_NC  | yes     | yes     |
| R_AARCH64_LDST64_ABS_LO12_NC  | yes     | yes     |
| R_AARCH64_LDST128_ABS_LO12_NC | yes     | yes     |

