/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>

// Implemented in posix/bionic/arch-arm/cacheflush.S
extern "C" int _TRaP_libc_cacheflush(long start, long end, long flags);

void os::Module::Section::flush_icache() {
  if (_TRaP_libc_cacheflush(reinterpret_cast<long>(m_start.to_ptr()), reinterpret_cast<long>(m_end.to_ptr()), 0) != 0) {
    os::API::DebugPrintf<1>("Could not flush ICACHE!\n");
  }
}

