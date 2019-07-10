/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>

// Implemented in posix/bionic/arch-arm/cacheflush.S
extern "C" int _TRaP_syscall_cacheflush(long start, long end, long flags);

void os::Module::Section::flush_icache() {
  if (_TRaP_syscall_cacheflush(reinterpret_cast<long>(m_start.to_ptr()),
                               reinterpret_cast<long>(m_end.to_ptr()),
                               0) != 0) {
    os::API::debug_printf<1>("Could not flush ICACHE!\n");
  }
}

