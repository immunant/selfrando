/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

struct trap_file_t;

struct trap_data_t {
    uintptr_t base_address;
    uint8_t *data;
    size_t size;
};

extern struct trap_file_t *open_trap_file(const char*);
extern struct trap_data_t read_trap_data(struct trap_file_t*);
extern void free_trap_data(struct trap_data_t*);
extern void close_trap_file(struct trap_file_t*);

