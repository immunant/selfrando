/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>

void os::Module::Section::flush_icache() {
    uint64_t ctr_value;
    __asm__ volatile ("mrs %0, ctr_el0" : "=r"(ctr_value));

    auto icache_line_size = 4 << ((ctr_value >>  0) & 0xf);
    auto dcache_line_size = 4 << ((ctr_value >> 16) & 0xf);

    // Flush the dcache first
    auto sec_start = start().to_ptr();
    auto sec_end = end().to_ptr();
    os::API::debug_printf<1>("Flushing icache range %p-%p\n",
                             sec_start, sec_end);
    for (auto ptr = sec_start; ptr < sec_end; ptr += dcache_line_size)
        __asm__ volatile ("dc cvau, %0" : : "r"(ptr) : "memory");

    // Memory barrier
    __asm__ volatile ("dsb ish" : : : "memory");

    // Now flush the icache lines
    for (auto ptr = sec_start; ptr < sec_end; ptr += icache_line_size)
        __asm__ volatile ("ic ivau, %0" : : "r"(ptr) : "memory");

    // Memory barrier
    __asm__ volatile ("isb" : : : "memory");
}

