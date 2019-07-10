/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once

#include <utility>

namespace Debug {
    void PrintfImpl(const char *fmt, ...);

    template<int level, typename... Args>
    static inline void printf(Args&&... args) {
        if (level <= RANDOLIB_DEBUG_LEVEL)
            PrintfImpl(std::forward<Args>(args)...);
    }
};

namespace Error {
    void printf(const char *fmt, ...);
};
