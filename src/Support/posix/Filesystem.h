/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#pragma once
#include <string>
#include <vector>

#include "Debug.h"

namespace Filesystem {

    std::string get_temp_dir();
    std::string get_temp_filename(std::string filename_tag, std::string filename_end = "");
    std::pair<int, std::string> create_temp_file(std::string filename_tag, std::string filename_end = "");
    std::pair<int, std::string> copy_to_temp_file(int source, std::string filename_tag, std::string filename_end = "");
    bool remove(std::string filename);

};
