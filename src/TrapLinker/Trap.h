/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstddef>

#if RANDOLIB_ARCH_SIZE == 32
typedef uint32_t TargetPtr;
typedef int32_t TargetOff;
typedef int32_t TargetPtrDiff;
#else
typedef uint64_t TargetPtr;
typedef int64_t TargetOff;
typedef int64_t TargetPtrDiff;
#endif // RANDOLIB_ARCH_SIZE

