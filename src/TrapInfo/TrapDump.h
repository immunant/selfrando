/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <TrapPlatform.h>

struct trap_file_t;

struct trap_data_t {
    trap_platform_t trap_platform;
    // Virtual address of .txtrp section
    uintptr_t txtrp_address;
    uintptr_t base_address;
    uint8_t *data;
    size_t size;
};

extern struct trap_file_t *open_trap_file(const char*);
extern struct trap_data_t read_trap_data(struct trap_file_t*);
extern void free_trap_data(struct trap_data_t*);
extern void close_trap_file(struct trap_file_t*);

