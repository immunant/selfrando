/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

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

    // Delta to add to all addresses to obtain .txtrp-relative values
    int64_t address_delta =
        (intptr_t)data.txtrp_address - (intptr_t)data.data;

    struct trap_header_t header = {};
    uint8_t *trap_ptr = data.data;
    trap_read_header(&header, &trap_ptr,
                     data.trap_platform, data.base_address);
    printf("Header: %08x Version: %02x Flags: %06x Ptrsize:%" PRIu64 "\n",
           header.flags, header.version, header.flags >> 8,
           header.pointer_size);

    if (trap_header_has_flag(&header, TRAP_HAS_NONEXEC_RELOCS)) {
        struct trap_reloc_t reloc;
        trap_address_t rel_addr = 0;
        trap_ptr = header.reloc_start;
        while (trap_read_reloc(&header, &trap_ptr, &rel_addr, &reloc)) {
            assert(rel_addr == reloc.address);
            printf("Rel[%" PRId64 "]@%" PRIx64 "=%" PRIx64 "+%" PRId64 "\n",
                   reloc.type, reloc.address + address_delta,
                   reloc.symbol, reloc.addend);
        }
    }

    size_t num_records = 0, num_symbols = 0;
    struct trap_record_t record;
    trap_ptr = header.record_start;
    while (trap_ptr < (data.data + data.size)) {
        trap_read_record(&header, &trap_ptr, NULL, &record);
        size_t first_ofs = record.first_symbol.address - record.address;
        printf("Record@%" PRIx64 "(sec+%zd)\n",
               record.address + address_delta, first_ofs);

        struct trap_symbol_t symbol;
        uint8_t *sym_ptr = record.symbol_start;
        trap_address_t sym_addr = record.address;
        while (sym_ptr < record.symbol_end) {
            trap_read_symbol(&header, &sym_ptr, &sym_addr, &symbol);
            assert(sym_addr == symbol.address);
            printf("  Sym@%" PRIx64 "/%" PRIx64 "[%" PRIx64 "] align:%ld\n",
                   symbol.address - record.address,
                   symbol.address + address_delta,
                   symbol.size,
                   (1L << symbol.p2align));
            num_symbols++;
        }

        if (trap_header_has_flag(&header, TRAP_HAS_RECORD_RELOCS)) {
            struct trap_reloc_t reloc;
            trap_address_t rel_addr = record.address;
            trap_pointer_t rel_ptr = record.reloc_start;
            while (rel_ptr < record.reloc_end &&
                   trap_read_reloc(&header, &rel_ptr, &rel_addr, &reloc)) {
                assert(rel_addr == reloc.address);
                printf("  Rel[%" PRId64 "]@%" PRIx64 "=%" PRIx64 "+%" PRId64 "\n",
                       reloc.type, reloc.address + address_delta,
                       reloc.symbol, reloc.addend);
            }
        }

        if (trap_header_has_flag(&header, TRAP_HAS_RECORD_PADDING)) {
            printf("  Padding[%" PRId64 "]@%" PRIx64 "/%" PRIx64 "\n",
                   record.padding_size,
                   record.padding_ofs,
                   record.padding_ofs + record.address + address_delta);
        }
        num_records++;
    }
    printf("Records:%zd\n", num_records);
    printf("Syms:%zd\n", num_symbols);

    free_trap_data(&data);
    close_trap_file(file);
    return 0;
}

