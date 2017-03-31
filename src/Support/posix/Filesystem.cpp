/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "Filesystem.h"
#include <unistd.h>
#include <fcntl.h>
#include <random>

std::string Filesystem::get_temp_dir() {
    const char *tempdir_env_vars[] = {
        "TMPDIR",
        "TMP",
        "TEMP",
        "TEMPDIR"
    };
    char *tempdir = nullptr;
    for (unsigned i = 0; i < 4; ++i) {
        if ((tempdir = getenv(tempdir_env_vars[i])) != nullptr)
            break;
    }
    return (tempdir == nullptr) ? "/tmp" : tempdir;
}

std::string Filesystem::get_temp_filename(std::string filename_tag) {
    std::string temp_path = get_temp_dir() + "/" + filename_tag + "-";

    // FIXME: is it OK to reinitialize the RNG on each call???
    std::random_device r;
    std::default_random_engine rng(r());
    std::uniform_int_distribution<char> uniform_dist(0, 61);
    for (unsigned i = 0; i < 10; ++i) {
        char rand_char = uniform_dist(rng);
        if (rand_char >= 52) {
            rand_char = '0' + (rand_char - 52);
        } else if (rand_char >= 26) {
            rand_char = 'A' + (rand_char - 26);
        } else {
            rand_char = 'a' + rand_char;
        }
        temp_path += rand_char;
    }

    return temp_path;
}

std::pair<int, std::string> Filesystem::create_temp_file(std::string filename_tag) {
    std::string temp_filename = get_temp_filename(filename_tag);
    int fd = open(temp_filename.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1)
        Error::printf("Could not create temporary file: %s", temp_filename.data());

    return std::make_pair(fd, temp_filename.data());
}


std::pair<int, std::string> Filesystem::copy_to_temp_file(int source, std::string filename_tag) {
    size_t BUFSIZE = 4096;
    char buf[BUFSIZE];
    ssize_t size;

    auto temp_file = create_temp_file(filename_tag);

    while ((size = read(source, buf, BUFSIZE)) > 0) {
        if(write(temp_file.first, buf, size) == -1)
            perror("write");
    }
    lseek(temp_file.first, 0, SEEK_SET);

    return temp_file;
}

bool Filesystem::remove(std::string filename) {
    return (unlink(filename.c_str()) == 0);
}
