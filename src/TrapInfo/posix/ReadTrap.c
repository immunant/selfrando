/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include <TrapDump.h>

struct trap_file_t {
    int fd;
    Elf *elf;
};

struct trap_file_t *open_trap_file(const char *filename) {
    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(EXIT_FAILURE, "Cannot initialize ELF library: %s", elf_errmsg(-1));

    struct trap_file_t *res = malloc(sizeof(struct trap_file_t));
    if (!res)
        errx(EXIT_FAILURE, "Cannot allocate memory for trap_file_t");

    res->fd = open(filename, O_RDONLY, 0);
    if (res->fd < 0)
        errx(EXIT_FAILURE, "Cannot open file: %s", filename);

    res->elf = elf_begin(res->fd, ELF_C_READ, NULL);
    if (res->elf == NULL)
        errx(EXIT_FAILURE, "Cannot read ELF file %s: %s",
             filename, elf_errmsg(-1));

    if (elf_kind(res->elf) != ELF_K_ELF)
        errx(EXIT_FAILURE, "File is not ELF: %s", filename);

    return res;
}

static Elf_Scn *find_txtrp_section(Elf *elf) {
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        errx(EXIT_FAILURE, "Could not find string section in file");

    Elf_Scn *scn;
    GElf_Shdr shdr;
    for (scn = elf_nextscn(elf, NULL);
         scn != NULL;
         scn = elf_nextscn(elf, scn)) {
        if (gelf_getshdr(scn, &shdr) == NULL)
            errx(EXIT_FAILURE, "Cannot get section header");

        const char *scn_name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (strcmp(scn_name, ".txtrp") == 0)
            return scn;
    }
    return NULL;
}

struct trap_data_t read_trap_data(struct trap_file_t *file) {
    struct trap_data_t res = { NULL, 0 };
    Elf_Scn *txtrp_scn = find_txtrp_section(file->elf);
    if (txtrp_scn == NULL)
        return res;

    Elf_Data *data = elf_getdata(txtrp_scn, NULL);
    for (data = elf_getdata(txtrp_scn, NULL);
         data != NULL;
         data = elf_getdata(txtrp_scn, data))
        res.size += data->d_size;

    res.data = malloc(res.size);
    uint8_t *ptr = res.data;
    for (data = elf_getdata(txtrp_scn, NULL);
         data != NULL;
         data = elf_getdata(txtrp_scn, data)) {
        memcpy(ptr, data->d_buf, data->d_size);
        ptr += data->d_size;
    }
    return res;
}

void free_trap_data(struct trap_data_t *data) {
    free(data->data);
    data->data = NULL;
    data->size = 0;
}

void close_trap_file(struct trap_file_t *file) {
    elf_end(file->elf);
    close(file->fd);
    free(file);
}
