/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <err.h>

#include <TrapInfo.h>
#include <TrapDump.h>

int main(int argc, const char *argv[]) {
    if (argc != 2)
        errx(EXIT_FAILURE, "Usage: %s <binary>", argv[0]);

    struct trap_file_t *file = open_trap_file(argv[1]);
    if (!file)
       errx(EXIT_FAILURE, "Cannot open binary file: %s", argv[1]);

    struct trap_data_t data = read_trap_data(file);
    if (data.data == NULL || data.size == 0)
        errx(EXIT_FAILURE, "File does not contain any TRaP data: %s", argv[1]);
    printf("Read TRaP data bytes: %zd\n", data.size);

    struct trap_header_t header;
    uint8_t *trap_ptr = data.data;
    trap_read_header(NULL, &trap_ptr, NULL, &header);
    printf("Header: %08x Version: %02x Flags: %06x\n",
           header.flags, header.version, header.flags >> 8);

    if (trap_header_has_flag(&header, TRAP_HAS_NONEXEC_RELOCS)) {
        struct trap_reloc_t reloc;
        uintptr_t rel_addr = 0;
        trap_ptr = header.reloc_start;
        while (trap_read_reloc(&header, &trap_ptr, &rel_addr, &reloc)) {
            assert(rel_addr == reloc.address);
            printf("Rel[%ld]@%lx=%lx+%ld\n",
                   reloc.type, reloc.address,
                   reloc.symbol ? (reloc.symbol + data.base_address) : 0,
                   reloc.addend);
        }
    }

    size_t num_records = 0, num_symbols = 0;
    struct trap_record_t record;
    trap_ptr = header.record_start;
    while (trap_ptr < (data.data + data.size)) {
        uintptr_t tmp_address = data.base_address;
        trap_read_record(&header, &trap_ptr, &tmp_address, &record);
        // FIXME: record addresses may be RVAs or GOT-relative
        size_t first_ofs = record.first_symbol.address - record.address;
        printf("Address: %08lx(sec+%ld)\n",
               record.address, first_ofs);

        struct trap_symbol_t symbol;
        uint8_t *sym_ptr = record.symbol_start;
        uintptr_t sym_addr = record.address;
        while (sym_ptr < record.symbol_end) {
            trap_read_symbol(&header, &sym_ptr, &sym_addr, &symbol);
            assert(sym_addr == symbol.address);
            // FIXME: we sometimes read the wrong symbol.address
            printf("  Sym@%lx/%lx[%lx] align:%ld\n",
                   symbol.address - record.address,
                   symbol.address,
                   symbol.size,
                   symbol.alignment);
            num_symbols++;
        }

        if (trap_header_has_flag(&header, TRAP_HAS_RECORD_RELOCS)) {
            struct trap_reloc_t reloc;
            uintptr_t rel_addr = record.address;
            trap_pointer_t rel_ptr = record.reloc_start;
            while (rel_ptr < record.reloc_end &&
                   trap_read_reloc(&header, &rel_ptr, &rel_addr, &reloc)) {
                assert(rel_addr == reloc.address);
                printf("  Rel[%ld]@%lx=%lx+%ld\n",
                       reloc.type, reloc.address,
                       reloc.symbol ? (reloc.symbol + data.base_address) : 0,
                       reloc.addend);
            }
        }

        if (trap_header_has_flag(&header, TRAP_HAS_RECORD_PADDING)) {
            printf("  Padding[%ld]@%lx/%lx\n",
                   record.padding_size,
                   record.padding_ofs,
                   record.padding_ofs + record.address);
        }
        num_records++;
    }
    printf("Records:%ld\n", num_records);
    printf("Syms:%ld\n", num_symbols);

    free_trap_data(&data);
    close_trap_file(file);
    return 0;
}

